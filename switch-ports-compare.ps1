<#
This PowerShell script logs into a UniFi Dream Machine Pro (UDM Pro), retrieves the configuration details of two specific ports on a specified switch, and displays the details side by side for easy comparison.

1. **Authentication**: Uses `Invoke-WebRequest` to log into the UDM Pro and retrieve a session token, ensuring the headers are captured correctly.
2. **CSRF Token Handling**: Extracts the `X-Csrf-Token` from the login response headers.
3. **Setting Headers**: Sets the `X-Csrf-Token` header for subsequent requests.
4. **Fetching Device Information**: Uses `Invoke-RestMethod` to retrieve information about the devices on the specified network.
5. **Finding the Specific Switch**: Filters out the switch with the specified MAC address.
6. **Finding Specific Ports**: Filters out the specific ports you want to compare based on the port index.
7. **Display Function**: A function to display port details side by side for easy comparison, using helper functions to convert status to strings.
8. **Displaying Port Details**: Calls the function for both ports.
9. **Logout**: Logs out from the UDM Pro.

Replace placeholders like `<udm-pro-ip>`, `<username>`, `<password>`, `<switchMac>`, `<port1>`, and `<port2>` with appropriate values. Adjust the port indices (`$port1` and `$port2`) to match the ports you are comparing.
2fa is not supported

Test this script in your environment and adjust as necessary for your specific UDM Pro setup.
#>

# Define controller URL, username, and password
$controllerUrl = "https://<udm-pro-ip>:443"
$username = "<username>"
$password = "<password>"

# Ports to compare (e.g., 1 and 2 for port index)
$port1 = 1  # Change to the correct port index
$port2 = 2  # Change to the correct port index

# Switch MAC address
$switchMac = "<switchMac>"

# Login to UDM Pro
$loginResponse = Invoke-WebRequest -Uri "$controllerUrl/api/auth/login" -Method Post -Body (@{ username = $username; password = $password } | ConvertTo-Json) -ContentType "application/json" -SessionVariable udmSession

# Extract CSRF Token from the login response headers
$csrfToken = $loginResponse.Headers['X-Csrf-Token']

# Set headers for subsequent requests
$headers = @{
    'X-Csrf-Token' = $csrfToken
    'Content-Type' = 'application/json'
}

# Fetch the switch information
$switches = Invoke-RestMethod -Uri "$controllerUrl/proxy/network/api/s/default/stat/device" -Method Get -WebSession $udmSession -Headers $headers

# Find the specific switch by MAC address
$switch = $switches.data | Where-Object { $_.mac -eq $switchMac }

# Get port details
$portDetails1 = $switch.port_table | Where-Object { $_.port_idx -eq $port1 }
$portDetails2 = $switch.port_table | Where-Object { $_.port_idx -eq $port2 }

# Function to display port details side by side
function Display-PortComparison {
    param (
        [PSCustomObject]$port1Details,
        [PSCustomObject]$port2Details
    )

    # Helper function to get status as a string
    function Get-StatusString($status) {
        if ($status -eq $true) {
            return "Enabled"
        } else {
            return "Disabled"
        }
    }

    # Helper function to get operational status as a string
    function Get-OperationalStatusString($status) {
        if ($status -eq $true) {
            return "Connected"
        } else {
            return "Disconnected"
        }
    }

    Write-Host "Property               Port 1                         Port 2"
    Write-Host "-------------------------------------------------------------"
    Write-Host ("Port Index:          {0,-30} {1}" -f $port1Details.port_idx, $port2Details.port_idx)
    Write-Host ("Port Name:           {0,-30} {1}" -f $port1Details.name, $port2Details.name)
    Write-Host ("Port Status:         {0,-30} {1}" -f (Get-StatusString $port1Details.enable), (Get-StatusString $port2Details.enable))
    Write-Host ("PoE Settings:        {0,-30} {1}" -f $port1Details.poe_mode, $port2Details.poe_mode)
    Write-Host ("VLAN Assignment:     {0,-30} {1}" -f $port1Details.vlan, $port2Details.vlan)
    Write-Host ("Duplex and Speed:    {0,-30} {1}" -f $port1Details.speed, $port2Details.speed)
    Write-Host ("Port Profile:        {0,-30} {1}" -f $port1Details.portconf_id, $port2Details.portconf_id)
    Write-Host ("Link Aggregation:    {0,-30} {1}" -f $port1Details.aggregate_id, $port2Details.aggregate_id)
    Write-Host ("Operational Status:  {0,-30} {1}" -f (Get-OperationalStatusString $port1Details.up), (Get-OperationalStatusString $port2Details.up))
    Write-Host ("Traffic (Rx/Tx):     {0,-30} {1}" -f "$($port1Details.rx_bytes) / $($port1Details.tx_bytes)", "$($port2Details.rx_bytes) / $($port2Details.tx_bytes)")
    Write-Host ""
}

# Display port comparison
Display-PortComparison -port1Details $portDetails1 -port2Details $portDetails2

# Logout from UDM Pro
Invoke-RestMethod -Uri "$controllerUrl/api/auth/logout" -Method Post -WebSession $udmSession -Headers $headers
