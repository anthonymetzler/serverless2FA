2FA Micro-Service - Authentication Done via Email

Service utilizes Serverless Framework and currently hosted on AWS. Consists of two API endpoints for generating and verifying Authentication Codes. Codes are valid for 30 minutes. Emails are dispatched through SendGrid.

Dev Endpoints
POST - https://XXXXXX.execute-api.us-east-1.amazonaws.com/dev/auth/create
GET - https://XXXXXX.execute-api.us-east-1.amazonaws.com/dev/auth/verify
