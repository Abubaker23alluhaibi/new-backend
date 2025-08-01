# Tabib IQ - Backend API

## 🚀 Deploy to Railway

This is the backend API for Tabib IQ medical platform.

### Setup Instructions:

1. **Clone this repository**
2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables in Railway:**
   - Go to your Railway project settings
   - Add the following environment variables:
     - `MONGO_URI`: Your MongoDB connection string
     - `JWT_SECRET`: Secret key for JWT tokens
     - `NODE_ENV`: Set to "production"
     - `PORT`: Railway will set this automatically

4. **Deploy:**
   - Connect your GitHub repository to Railway
   - Railway will automatically build and deploy

### Environment Variables:
- `MONGO_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT authentication
- `NODE_ENV`: Environment (production/development)
- `PORT`: Server port (set automatically by Railway)

### API Endpoints:
- `GET /api/health`: Health check endpoint
- `POST /api/users/register`: User registration
- `POST /api/users/login`: User login
- `POST /api/doctors/register`: Doctor registration
- `POST /api/doctors/login`: Doctor login
- `GET /api/doctors`: Get all doctors
- `POST /api/appointments`: Book appointment
- `GET /api/appointments`: Get appointments
- And many more...

### Features:
- User authentication and authorization
- Doctor management system
- Appointment booking system
- File upload for documents
- Email notifications
- WhatsApp integration
- Multi-language support

### Tech Stack:
- Node.js
- Express.js
- MongoDB with Mongoose
- JWT for authentication
- Multer for file uploads
- Nodemailer for emails
- Twilio for WhatsApp

### Health Check:
The API includes a health check endpoint at `/api/health` that Railway uses to monitor the service. 