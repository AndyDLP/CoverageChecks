Describe 'Test-IsDc' {
    Set-StrictMode -Version latest
    Context 'When no parameters are passed' {
        It 'Should return false' {
            Test-IsDc | Should -Be $false
        }
    }
    Context 'When the remote computer is a backup DC' {
        Mock -ModuleName ECI-Utilities Invoke-Command {return $true}
        Mock -ModuleName ECI-Utilities Test-Connection {return $true}
        Mock -ModuleName ECI-Utilities Test-WSMan {return $true}
        Mock -ModuleName ECI-Utilities Get-WmiObject {
            return [PSCustomObject]@{
                DomainRole = 4
            }
        }
        It 'Should return true' {
            Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
        }
    }
    Context 'When the remote computer is a primary DC' {
        Mock -ModuleName ECI-Utilities Invoke-Command {return $true}
        Mock -ModuleName ECI-Utilities Test-Connection {return $true}
        Mock -ModuleName ECI-Utilities Test-WSMan {return $true}
        Mock -ModuleName ECI-Utilities Get-WmiObject {
            return [PSCustomObject]@{
                DomainRole = 5
            }
        }
        It 'Should return true' {
            Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
        }
    }
    Context 'When the remote computer is not a DC' {
        Mock -ModuleName ECI-Utilities Invoke-Command {return $true}
        Mock -ModuleName ECI-Utilities Test-Connection {return $true}
        Mock -ModuleName ECI-Utilities Test-WSMan {return $true}
        Mock -ModuleName ECI-Utilities Get-WmiObject {
            return [PSCustomObject]@{
                DomainRole = 3
            }
        }
        It 'Should return true' {
            Test-IsDc -ComputerName 'TestDC1' | Should -Be $true
        }
    }
    Context 'When the remote computer is not pingable' {
        Mock -ModuleName ECI-Utilities Invoke-Command {return $true}
        Mock -ModuleName ECI-Utilities Test-Connection {return $false}
        Mock -ModuleName ECI-Utilities Test-WSMan {return $true}
        Mock -ModuleName ECI-Utilities Get-WmiObject {
            return [PSCustomObject]@{
                DomainRole = 3
            }
        }
        It 'Should throw an error' {
            { Test-IsDc -ComputerName 'TestDC1' } | Should -Throw
        }
    }
    Context 'When WSMan is not available on the remote computer' {
        Mock -ModuleName ECI-Utilities Invoke-Command {return $true}
        Mock -ModuleName ECI-Utilities Test-Connection {return $true}
        Mock -ModuleName ECI-Utilities Test-WSMan { throw "error" }
        Mock -ModuleName ECI-Utilities Get-WmiObject {
            return [PSCustomObject]@{
                DomainRole = 3
            }
        }
        Test-IsDc -ComputerName 'TestDC1' | Out-Null
        It 'Should failback to trying via Get-WmiObject' {
            Assert-MockCalled -CommandName 'Get-WmiObject' -ModuleName ECI-Utilities -ParameterFilter { $ComputerName -eq 'TestDC1' } -Exactly -Times 1
        }
    }
}