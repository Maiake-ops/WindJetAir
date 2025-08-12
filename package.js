{
  "name": "windjetair-auth",
  "version": "1.0.0",
  "description": "Authentication server for WindJetAir",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "bcrypt": "^5.1.0",
    "express-rate-limit": "^6.7.0",
    "helmet": "^6.1.5",
    "express-session": "^1.17.3"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
