require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const Redis = require("ioredis");
const cors = require("cors");
const helmet = require("helmet");
const postRoutes = require("./routes/post");
const errorHandler = require("./middleware/errorHandler");
const logger = require("./utils/logger");
const { rateLimiterRedis, RateLimiterRedis } = require("rate-limiter-flexible");
const { rateLimit } = require("express-rate-limit");
const { RedisStore } = require("rate-limit-redis");
const { log } = require("winston");

const app = express();
const PORT = process.env.PORT || 3002;

//connect to mongodb
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => logger.info("Connected to mongodb"))
  .catch((e) => logger.error("Mongo connection error", e));

const redisClient = new Redis(process.env.REDIS_URL);

//middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  logger.info(`Received ${req.method} request to ${req.url}`);
  logger.info(`Request body, ${req.body}`);
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
app.use("/api/posts/all-posts", sensitiveEndpointsLimiter);

//routes -> pass redis client to routes
app.use(
  "/api/posts",
  (req, res, next) => {
    req.redisClient = redisClient;
    next();
  },
  postRoutes,
);

app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`Post service running on port ${PORT}`);
});

//unhandled promise rejection
process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at", promise, "reason:", reason);
});
