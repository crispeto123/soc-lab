// IaC INSEGURA A PROPÓSITO — solo para laboratorio. No desplegar.
param location string = resourceGroup().location

// VULN: acceso público a blobs, HTTP permitido, TLS 1.0, sin restricción de red
resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stlabvibecoded001'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    networkAcls: { defaultAction: 'Allow' }
  }
}

// VULN: Key Vault sin purge protection ni soft delete, acceso público
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-lab-vibecoded-001'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableSoftDelete: false
    publicNetworkAccess: 'Enabled'
    accessPolicies: []
  }
}

// VULN: App Service sin HTTPS obligatorio y FTP habilitado
resource plan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: 'plan-lab'
  location: location
  sku: { name: 'B1' }
}

resource web 'Microsoft.Web/sites@2023-01-01' = {
  name: 'app-lab-vibecoded-001'
  location: location
  properties: {
    serverFarmId: plan.id
    httpsOnly: false
    siteConfig: {
      ftpsState: 'AllAllowed'
      minTlsVersion: '1.0'
    }
  }
}
