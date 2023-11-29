Invoke-WebRequest https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv -OutFile $env:userprofile\desktop\DotGovAllDomains.csv

$DotGovDomains = import-csv $env:USERPROFILE\desktop\DotGovAllDomains.csv | Select-Object *,@{Name="DMARC Policy";Expression={""}}
Remove-Item $env:USERPROFILE\desktop\DotGovAllDomains.csv

# Ingest only actual States
$StateDomains = $DotGovDomains | ?{$_."Domain Type" -eq "State" -and $_.State -notmatch "^(VI|MP|GU|AS|PR)$"}

# Loop for domains
foreach($Row in $StateDomains){

	$domain = $Row."Domain Name"
    	$dmarc = $null
	
    # get DMARC record for domain
    $dmarc = Resolve-DnsName -Type TXT -Name "_dmarc.$domain" -errorvariable err -erroraction silentlycontinue

    # sort based on DMARC record data
    if($dmarc -eq $null -or $dmarc.type -eq "SOA"){
        write-host -foregroundcolor magenta $state - $domain - No DMARC record exists!
        
	$Row."DMARC Policy" = "norecord"
    }
    elseif($dmarc.strings -like "*p=none*"){
        write-host -foregroundcolor red $state - $domain - $dmarc.strings
        
	$Row."DMARC Policy" = "none"
    }
    elseif($dmarc.strings -like "*p=quarantine*"){
        write-host -foregroundcolor yellow $state - $domain - $dmarc.strings
        
	$Row."DMARC Policy" = "quarantine"
    }
    elseif($dmarc.strings -like "*p=reject*"){
        write-host -foregroundcolor green $state - $domain - $dmarc.strings
        
	$Row."DMARC Policy" = "reject"
    }
	else{
		write-host -foregroundcolor magenta $state - $domain - No DMARC record exists!
        
		$Row."DMARC Policy" = "norecord"}
}

$StateDomains | Export-CSV $env:userprofile\desktop\StateDMARC.csv -NoTypeInformation
