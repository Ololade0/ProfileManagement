# User Management Profile API

A Django-based API for user registration, authentication, and profile management, built with **Django Ninja** and **DRF Tokens** for authentication. Users can sign up, log in, and manage their profiles through a set of simple API endpoints.

## Project Overview

- **Project Name**: `profilemanagement`
- **App Name**: `users`
- **Tech Stack**: Django, Django Ninja, DRF Tokens, Pydantic, SQLite (or other databases)
- **Features**:
  - User Registration (Sign-Up)
  - User Authentication (Login with Token)
  - Retrieve User Profile



 **Clone the Repository**:
   ```bash
   git clone https://github.com/Ololade0/ProfileManagement.git

 API Documentation
Django Ninja provides an auto-generated documentation for your API.
 You can access it at: http://127.0.0.1:8000/api/docs

API Endpoints
1. User Sign-Up
URL: POST /api/user/signup
Description: Registers a new user.

2. User Login
URL: POST /api/user/login
Description: Authenticates a user and returns a token.

3. Get User Profile
URL: GET /api/user/profile
Description: Retrieves the authenticated user's profile.
Headers: Authorization: Token <your_token>


Contact
If you have any questions or feedback, feel free to reach out at [adesuyiololade@gmail.com].
