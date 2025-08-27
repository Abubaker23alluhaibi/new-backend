# 🚀 Quick Test Guide for TabibiQ Backend

## 🔍 Test Health Check Endpoints

### 1. Test Root Endpoint
```bash
curl http://localhost:10000/
```

Expected Response:
```json
{
  "message": "TabibiQ Backend API is running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0"
}
```

### 2. Test Health Endpoint
```bash
curl http://localhost:10000/health
```

Expected Response:
```json
{
  "status": "OK",
  "message": "Server is running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 123.456,
  "environment": "development"
}
```

### 3. Test API Health Endpoint
```bash
curl http://localhost:10000/api/health
```

Expected Response:
```json
{
  "status": "OK",
  "message": "Server is running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 123.456,
  "environment": "development"
}
```

## 🧪 Test with Browser

Open these URLs in your browser:
- `http://localhost:10000/`
- `http://localhost:10000/health`
- `http://localhost:10000/api/health`

## 🐳 Test with Docker

```bash
# Build and run
docker build -t tabibiq-backend .
docker run -p 10000:10000 tabibiq-backend

# Test endpoints
curl http://localhost:10000/
```

## 🚂 Test on Railway

After deploying to Railway:

```bash
# Get your Railway URL
railway status

# Test health endpoints
curl https://your-railway-url.railway.app/
curl https://your-railway-url.railway.app/health
curl https://your-railway-url.railway.app/api/health
```

## ❌ Common Issues & Solutions

### Health Check Fails
- **Port already in use**: Change PORT in env.local
- **MongoDB connection failed**: Check MONGO_URI
- **Permission denied**: Run with elevated privileges

### CORS Issues
- **Frontend can't connect**: Check CORS_ORIGIN setting
- **Preflight failed**: Verify CORS configuration

### File Upload Issues
- **Uploads directory missing**: Create uploads/ folder
- **File size too large**: Check MAX_FILE_SIZE setting

## 📊 Monitor Logs

### Local Development
```bash
npm run dev
# Watch console output for errors
```

### Railway
```bash
railway logs
# Check for deployment and runtime errors
```

## 🔧 Environment Variables Check

Verify these are set correctly:
```bash
echo $NODE_ENV
echo $PORT
echo $MONGO_URI
echo $JWT_SECRET
```

## 🚨 Emergency Reset

If everything fails:
```bash
# Clean install
npm run clean

# Reset environment
cp env.local.example env.local
# Edit env.local with correct values

# Restart
npm run dev
```

## 📱 Test Frontend Connection

Update your frontend environment:
```env
REACT_APP_API_URL=http://localhost:10000
```

Test API calls from frontend to backend.

## ✅ Success Checklist

- [ ] Server starts without errors
- [ ] Health endpoints return 200 OK
- [ ] MongoDB connects successfully
- [ ] Frontend can connect to backend
- [ ] File uploads work
- [ ] Authentication endpoints work
- [ ] Railway deployment successful

## 🆘 Need Help?

1. Check Railway logs: `railway logs`
2. Check local logs: `npm run dev`
3. Verify environment variables
4. Test endpoints individually
5. Check MongoDB connection
6. Verify CORS settings 