# 🚀 Backend Deployment Guide - Railway

## Quick Deploy Steps:

### 1. Prepare Repository
- This folder contains all backend files ready for Railway deployment
- No `node_modules` included (will be installed automatically)

### 2. Deploy to Railway

#### Option A: Using Railway CLI
```bash
# Install Railway CLI
npm i -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Deploy
railway up
```

#### Option B: Using Railway Dashboard
1. Go to [railway.app](https://railway.app)
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Import your repository
5. Select the `backend-deploy` folder
6. Configure environment variables
7. Deploy!

### 3. Environment Variables Setup
In Railway dashboard, add:
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/tabibiq
JWT_SECRET=your-super-secret-jwt-key-here
NODE_ENV=production
```

### 4. MongoDB Setup
1. Create MongoDB Atlas account
2. Create new cluster
3. Get connection string
4. Add to Railway environment variables

### 5. Domain Setup
- Railway will provide a `.railway.app` domain
- You can add custom domain in project settings

### 6. Health Check
The API includes a health check endpoint:
```
GET https://your-app.railway.app/api/health
```

## Troubleshooting:
- If deployment fails, check Node.js version (should be 16+)
- Make sure MongoDB connection string is correct
- Check Railway logs for specific errors
- Ensure all environment variables are set

## Monitoring:
- Railway provides built-in monitoring
- Check logs in Railway dashboard
- Monitor resource usage

## Support:
- Railway Documentation: https://docs.railway.app
- MongoDB Atlas: https://docs.atlas.mongodb.com 