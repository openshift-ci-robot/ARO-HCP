@description('If set to true, the cluster will not be deleted automatically after few days.')
param persistTagValue bool = false

@description('Name of the hypershift cluster')
param clusterName string

@description('Name of the test VM')
param vmName string = '${clusterName}-test-vm'

@description('SSH public key for the VM')
param sshPublicKey string

@description('List of authorized IP ranges for API server access (will be populated with VM IP after deployment)')
param authorizedCidrs array = []

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

// Deploy test VM first to get its IP
module testVM 'modules/test-vm.bicep' = {
  name: 'testVM'
  params: {
    vmName: vmName
    vnetName: customerInfra.outputs.vnetName
    subnetName: customerInfra.outputs.vnetSubnetName
    sshPublicKey: sshPublicKey
  }
}

// Deploy cluster with VM's public IP in authorized CIDRs
module cluster 'modules/cluster-with-authorized-cidrs.bicep' = {
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
    authorizedCidrs: empty(authorizedCidrs) ? ['${testVM.outputs.publicIP}/32'] : authorizedCidrs
  }
  dependsOn: [
    testVM
  ]
}

output vmPublicIP string = testVM.outputs.publicIP
output vmPrivateIP string = testVM.outputs.privateIP
output clusterName string = cluster.outputs.name
