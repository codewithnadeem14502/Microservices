require("dotenv").config();
const mongoose = require("mongoose");
const express = require("express");
const logger = require("../utils/logger");
const { log } = require("winston");
const helmet = require("helmet");
const cors = require("cors");
const { rateLimiterRedis, RateLimiterRedis } = require("rate-limiter-flexible");
const Redis = require("ioredis");
const { RedisStore } = require("rate-limit-redis");
const { rateLimit } = require("express-rate-limit");
const routes = require("../routes/identity-service");
const errorHandler = require("../middleware/errorHandler");

const app = express();
const PORT = process.env.PORT || 3001;

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => logger.info("Connected to mongodb!"))
  .catch((e) => logger.error("Mongodb connection issue ", e));

const redisClient = new Redis(process.env.REDIS_URL);
//   middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  logger.info(`Received ${req.method} request to ${req.url}`);
  logger.info(`Request body: ${JSON.stringify(req.body)}`);
  next();
});

// DDOS - protection and rate limiter
const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: "middleware",
  points: 10,
  duration: 1,
});

// middleware for rate limiter
app.use((req, res, next) => {
  rateLimiter
    .consume(req.ip)
    .then(() => next())
    .catch(() => {
      logger.warn(`Rate limit exceed for this IP: ${req.ip}`);
      res.status(429).json({
        success: false,
        message: "To many requests",
      });
    });
});

// Rate limiter for sensitive endpoints

const sensitiveEndpointsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15Mins
  max: 50, // many no of request
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Sensitive endpoint rate limit exceed for this IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      message: "To many requests",
    });
  },
  store: new RedisStore({
    // new way
    sendCommand: (...args) => redisClient.call(args[0], ...args.slice(1)),
  }),
});

// Apply the sensitive for routes
app.use("/api/auth/register", sensitiveEndpointsLimiter);
//  other router ( non sensitive )
app.use("/api/auth", routes);

// error handler
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(` Identity service is listen on Port: ${PORT}`);
});

process.on("unhandleRejection", (reason, promise) => {
  logger.error("Unhandle Rejection at ", promise, "reason:", reason);
});
