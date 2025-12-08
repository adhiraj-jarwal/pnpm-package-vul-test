# API Documentation

## Overview

This document describes the API endpoints for the test project.

## Endpoints

### GET /api/health
Returns the health status of the application.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-12-08T21:00:00Z"
}
```

### GET /api/version
Returns the application version.

**Response:**
```json
{
  "version": "1.0.0"
}
```

## Authentication

All endpoints require a valid API key in the `Authorization` header.

Example:
```
Authorization: Bearer YOUR_API_KEY
```

