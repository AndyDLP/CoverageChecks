Describe 'Test-IsDc' {
    Set-StrictMode -Version latest
    InModuleScope ECI-Utilities {
        Context 'When no parameters are passed' {
            It 'Should return false' {
                Test-IsDc | Should -Be $false
            }
        }
        Context 'When the remote computer is a backup DC' {
            Mock Invoke-Command {return $true}
            Mock Test-Connection {return $true}
            Mock Test-WSMan {return $true}
            Mock Get-WmiObject {
                return [PSCustomObject]@{
                    DomainRole = 4
                }
            }
            It 'Should return true' {
                Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
            }
        }
        Context 'When the remote computer is a primary DC' {
            Mock Invoke-Command {return $true}
            Mock Test-Connection {return $true}
            Mock Test-WSMan {return $true}
            Mock Get-WmiObject {
                return [PSCustomObject]@{
                    DomainRole = 5
                }
            }
            It 'Should return true' {
                Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
            }
        }
        Context 'When the remote computer is not a DC' {
            Mock Invoke-Command {return $true}
            Mock Test-Connection {return $true}
            Mock Test-WSMan {return $true}
            Mock Get-WmiObject {
                return [PSCustomObject]@{
                    DomainRole = 3
                }
            }
            It 'Should return true' {
                Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
            }
        }
        Context 'When the remote computer is not pingable' {
            Mock Invoke-Command {return $true}
            Mock Test-Connection {return $false}
            Mock Test-WSMan {return $true}
            Mock Get-WmiObject {
                return [PSCustomObject]@{
                    DomainRole = 3
                }
            }
            It 'Should throw an error' {
                { Test-IsDc -ComputerName 'TestDC1' } | Should -Throw
            }
        }
        Context 'When WSMan is not available on the remote computer' {
            Mock Invoke-Command {return $true}
            Mock Test-Connection {return $true}
            Mock Test-WSMan { throw "error" }
            Mock Get-WmiObject {
                return [PSCustomObject]@{
                    DomainRole = 3
                }
            }
            Test-IsDc -ComputerName 'TestDC1' | Out-Null
            It 'Should failback to trying via Get-WmiObject' {
                Assert-MockCalled -CommandName 'Get-WmiObject' -ModuleName ECI-Utilities -ParameterFilter { $ComputerName -eq 'TestDC1' } -Exactly -Times 1 -Scope It
            }
        }
    }
}