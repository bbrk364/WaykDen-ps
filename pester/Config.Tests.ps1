Import-Module "$PSScriptRoot/../WaykDen"

Describe 'Wayk Den config' {
	InModuleScope WaykDen {
		Context 'Fresh environment' {
			It 'Creates new configuration with realm and external url' {
                New-WaykDenConfig -ConfigPath $TestDrive `
                    -Realm 'buzzword.marketing' -ExternalUrl 'https://den.buzzword.marketing'
                $(Get-WaykDenConfig -ConfigPath $TestDrive).Realm | Should -Be 'buzzword.marketing'
                $(Get-WaykDenConfig -ConfigPath $TestDrive).ExternalUrl | Should -Be 'https://den.buzzword.marketing'
			}
            It 'Sets and clears MongoDB configuration' {
                Set-WaykDenConfig -ConfigPath $TestDrive `
                    -MongoExternal $true -MongoUrl 'mongodb://mongo-server:27017'
                $config = Get-WaykDenConfig -ConfigPath $TestDrive
                $config.MongoExternal | Should -Be $true
                $config.MongoUrl | Should -Be 'mongodb://mongo-server:27017'
                Clear-WaykDenConfig -ConfigPath $TestDrive 'Mongo*'
                $config = Get-WaykDenConfig -ConfigPath $TestDrive
                $config.MongoExternal | Should -Be $false
                $config.MongoUrl | Should -BeNullOrEmpty
			}
		}
	}
}
