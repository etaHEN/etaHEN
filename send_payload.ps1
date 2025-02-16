<#
.SYNOPSIS
  Sends the contents of a file to a specified IP address and port using PowerShell.

.DESCRIPTION
  This script reads the contents of a file and sends it over a TCP connection
  to a specified IP address and port.  It handles potential errors and
  provides basic feedback, including connection failure detection.

.PARAMETER Payload
  The path to the file whose contents will be sent.

.PARAMETER IP
  The IP address to send the data to.

.PARAMETER Port
  The port number to connect to.

.EXAMPLE
  .\send_payload.ps1 -Payload "C:\xxx\xxx\payload.elf" -IP "192.168.x.xxx" -Port 9021

.NOTES
  - Requires PowerShell 3.0 or later.
  - Handles potential exceptions during socket creation and data transmission.
  - Consider error handling and security implications in production environments.
#>

param (
  [Parameter(Mandatory = $true, HelpMessage = "The path to the payload to send.")]
  [string]$Payload,

  [Parameter(Mandatory = $true, HelpMessage = "The IP address to send the data to.")]
  [string]$IP,

  [Parameter(Mandatory = $true, HelpMessage = "The port number to connect to.")]
  [int]$Port
)


# Check if the file exists before proceeding
if (!(Test-Path -Path $Payload -PathType Leaf)) {
  Write-Host "The specified payload file '$Payload' does not exist, Press any key to exit..." -ForegroundColor Red
  exit
}

try {
  # Create a TCP client object
  $tcpClient = New-Object System.Net.Sockets.TcpClient

  Write-Host "Connecting to ${IP}:$Port...."

  # Attempt to connect with a timeout
  $connectTimeoutMs = 5000 # 5 seconds timeout
  $connectResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
  $connected = $connectResult.AsyncWaitHandle.WaitOne($connectTimeoutMs)

  if (!$connected) {
    # Connection timed out
    Write-Host "Failed to connect to ${IP}:$Port within $connectTimeoutMs ms. Connection timed out, Press any key to exit..." -ForegroundColor Red
    $tcpClient.Close() # Ensure the client is closed
    exit  # Exit the script if connection fails
  }
  
  # Complete the connection
  $tcpClient.EndConnect($connectResult)
  
  # Get the network stream
  $stream = $tcpClient.GetStream()

  # Read the file content as a byte array
  Write-Verbose "Reading file content from $Payload..."
  $fileContent = [System.IO.File]::ReadAllBytes($Payload)

  # Send the data
  Write-Verbose "Sending data..."
  $stream.Write($fileContent, 0, $fileContent.Length)

  # Flush the stream to ensure all data is sent
  $stream.Flush()

  Write-Host "Successfully sent file '$Payload' to ${IP}:$Port, press any key to exit"

  # Shutdown and close the connection
  $stream.Close()
  $tcpClient.Close()

}
catch {
  Write-Error "An error occurred: $($_.Exception.Message), press any key to exit"
  Write-Error $_.Exception.StackTrace
}
finally {
  # Ensure resources are cleaned up even if an error occurs
  if ($stream) {
    try { $stream.Dispose() } catch {} # Handle potential disposal errors
  }
  if ($tcpClient) {
    try { $tcpClient.Close() } catch {} # Handle potential close errors
  }
  [System.Console]::ReadKey() | Out-Null
}
