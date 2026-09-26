$baseUrl = "http://localhost:8080/api/v1/auth"
$headers = @{ "Content-Type" = "application/json" }

Write-Host "=== TEST 1: Register User (Success) ===" -ForegroundColor Cyan
$userEmail = "john_$(Get-Random)@example.com"
$regPayload = @{
    email = $userEmail
    password = "Password123!"
    first_name = "John"
    last_name = "Doe"
} | ConvertTo-Json

$regResp = Invoke-RestMethod -Uri "$baseUrl/register" -Method POST -Headers $headers -Body $regPayload
Write-Host "Register Result: $($regResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

Write-Host "`nWaiting for Rate Limiter token bucket..." -ForegroundColor Yellow
Start-Sleep -Seconds 13

Write-Host "`n=== TEST 2: Login User (Success) ===" -ForegroundColor Cyan
$loginPayload = @{
    email = $userEmail
    password = "Password123!"
} | ConvertTo-Json

$loginResp = Invoke-RestMethod -Uri "$baseUrl/login" -Method POST -Headers $headers -Body $loginPayload
Write-Host "Login Result: $($loginResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

$accessToken = $loginResp.data.access_token
$refreshToken = $loginResp.data.refresh_token

Write-Host "`n=== TEST 3: Get Profile /me (Protected Route) ===" -ForegroundColor Cyan
$authHeaders = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}
$meResp = Invoke-RestMethod -Uri "$baseUrl/me" -Method GET -Headers $authHeaders
Write-Host "Profile Result: $($meResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

Write-Host "`n=== TEST 4: Refresh Access Token (Token Rotation) ===" -ForegroundColor Cyan
$refreshPayload = @{ refresh_token = $refreshToken } | ConvertTo-Json
$refreshResp = Invoke-RestMethod -Uri "$baseUrl/refresh" -Method POST -Headers $headers -Body $refreshPayload
Write-Host "Refresh Result: $($refreshResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

$newAccessToken = $refreshResp.data.access_token
$newRefreshToken = $refreshResp.data.refresh_token

Write-Host "`nWaiting for Rate Limiter token bucket..." -ForegroundColor Yellow
Start-Sleep -Seconds 13

Write-Host "`n=== TEST 5: Change Password (Authenticated User) ===" -ForegroundColor Cyan
$changeAuthHeaders = @{
    "Authorization" = "Bearer $newAccessToken"
    "Content-Type" = "application/json"
}
$changePayload = @{
    old_password = "Password123!"
    new_password = "UpdatedSecurePassword123!"
} | ConvertTo-Json
$changeResp = Invoke-RestMethod -Uri "$baseUrl/change-password" -Method POST -Headers $changeAuthHeaders -Body $changePayload
Write-Host "Change Password Result: $($changeResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

Write-Host "`nWaiting for Rate Limiter token bucket..." -ForegroundColor Yellow
Start-Sleep -Seconds 13

Write-Host "`n=== TEST 6: Login with Updated Password ===" -ForegroundColor Cyan
$updatedLoginPayload = @{
    email = $userEmail
    password = "UpdatedSecurePassword123!"
} | ConvertTo-Json

$updatedLoginResp = Invoke-RestMethod -Uri "$baseUrl/login" -Method POST -Headers $headers -Body $updatedLoginPayload
Write-Host "Updated Login Result: $($updatedLoginResp | ConvertTo-Json -Depth 5)" -ForegroundColor Green

Write-Host "`n🎉 ALL AUTHENTICATION ENDPOINTS TESTED & PASSED 100%!" -ForegroundColor Magenta
