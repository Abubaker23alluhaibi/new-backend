# TabibiQ Backend API

Backend API for TabibiQ medical platform built with Node.js, Express, and MongoDB.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- MongoDB Atlas account
- Railway account (for deployment)

### Local Development
```bash
# Install dependencies
npm install

# Copy environment file
cp env.local.example env.local

# Update environment variables in env.local
# Set your MongoDB URI, JWT secret, etc.

# Start development server
npm run dev
```

### Production Deployment on Railway
```bash
# Deploy to Railway
npm run railway:deploy

# Check status
npm run railway:status

# View logs
npm run railway:logs
```

## 🔧 Environment Variables

### Required
- `PORT` - Server port (default: 10000)
- `MONGO_URI` - MongoDB connection string
- `JWT_SECRET` - Secret for JWT tokens
- `NODE_ENV` - Environment (production/development)

### Optional
- `CORS_ORIGIN` - Allowed CORS origins
- `API_URL` - Backend API URL
- `CLOUDINARY_*` - Cloudinary configuration
- `MAX_FILE_SIZE` - Maximum file upload size
- `UPLOAD_PATH` - File upload directory

## 📡 API Endpoints

### Health Check
- `GET /` - Root endpoint
- `GET /health` - Health check
- `GET /api/health` - API health check

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/doctor-login` - Doctor login
- `POST /auth/doctor-register` - Doctor registration

### Appointments
- `GET /appointments` - Get appointments
- `POST /appointments` - Create appointment
- `PUT /appointments/:id` - Update appointment
- `DELETE /appointments/:id` - Delete appointment

### Doctors
- `GET /doctors` - Get doctors
- `POST /doctors` - Create doctor
- `PUT /doctors/:id` - Update doctor
- `DELETE /doctors/:id` - Delete doctor

### Users
- `GET /users` - Get users
- `PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user

## 🏗️ Project Structure

```
backend-iq/
├── server.js          # Main server file
├── package.json       # Dependencies and scripts
├── railway.toml       # Railway configuration
├── Dockerfile         # Docker configuration
├── .dockerignore      # Docker ignore file
├── models/            # Database models
├── uploads/           # File uploads directory
└── env.local          # Local environment variables
```

## 🚀 Deployment

### Railway (Recommended)
1. Connect your GitHub repository to Railway
2. Railway will automatically detect the configuration
3. Set environment variables in Railway dashboard
4. Deploy with `npm run railway:deploy`

### Docker
```bash
# Build image
docker build -t tabibiq-backend .

# Run container
docker run -p 10000:10000 tabibiq-backend
```

## 🔍 Troubleshooting

### Health Check Fails
- Check if server is running on correct port
- Verify environment variables are set
- Check Railway logs for errors

### MongoDB Connection Issues
- Verify MONGO_URI is correct
- Check MongoDB Atlas network access
- Ensure database user has correct permissions

### CORS Issues
- Verify CORS_ORIGIN is set correctly
- Check if frontend URL is in allowed origins

## 📝 Logs

### Local
```bash
npm run dev
```

### Railway
```bash
npm run railway:logs
```

## 🔒 Security Features

- Helmet.js for HTTP headers security
- CORS protection
- Rate limiting
- MongoDB injection protection
- XSS protection
- JWT authentication
- Input sanitization

## 📊 Health Monitoring

The API includes built-in health monitoring:
- Root endpoint (`/`) for basic health check
- `/health` endpoint for detailed status
- `/api/health` for API-specific health check

Railway uses these endpoints for automatic health monitoring and restart policies.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details 