# Spring Security Skeleton

## Build
* run docker-compose
* rename and adjust env.dev.properties.dev to env.properties
* run application

## Paths
[POST] localhost:8080/api/v1/auth/register
Body:
{
"email": "test@gmail.com",
"password": "12345",
"firstname": "swoosh",
"lastname": "kid"
}

[POST] localhost:8080/api/v1/auth/authenticate
Body:
{
"email": "test@gmail.com",
"password": "12345"
}

[GET] localhost:8080/api/v1/demo/hello
Bearer Token: {$validToken}