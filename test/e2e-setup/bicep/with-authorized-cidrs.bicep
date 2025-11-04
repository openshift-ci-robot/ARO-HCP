@description('If set to true, the cluster will not be deleted automatically after few days.')
param persistTagValue bool = false

@description('Name of the hypershift cluster')
param clusterName string

@description('List of authorized IP ranges for API server access')
param authorizedCidrs array = [
  '10.0.0.0/16'
  '192.168.1.0/24'
]

module customerInfra 'modules/customer-infra.bicep' = {
  name: 'customerInfra'
  params: {
    persistTagValue: persistTagValue
  }
}

module managedIdentities 'modules/managed-identities.bicep' = {
  name: 'managedIdentities'
  params: {
    clusterName: clusterName
    vnetName: customerInfra.outputs.vnetName
    subnetName: customerInfra.outputs.vnetSubnetName
    nsgName: customerInfra.outputs.nsgName
    keyVaultName: customerInfra.outputs.keyVaultName
  }
}

module AroHcpCluster 'modules/cluster-with-authorized-cidrs.bicep' = {
  name: 'cluster'
  params: {
    clusterName: clusterName
    vnetName: customerInfra.outputs.vnetName
    subnetName: customerInfra.outputs.vnetSubnetName
    nsgName: customerInfra.outputs.nsgName
    userAssignedIdentitiesValue: managedIdentities.outputs.userAssignedIdentitiesValue
    identityValue: managedIdentities.outputs.identityValue
    keyVaultName: customerInfra.outputs.keyVaultName
    etcdEncryptionKeyName: customerInfra.outputs.etcdEncryptionKeyName
    authorizedCidrs: authorizedCidrs
  }
}
