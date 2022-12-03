# Array for States
    $states = @("Alabama","Alaska","Arizona","Arkansas","California","Colorado","Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho","Illinois","Indiana","Iowa","Kansas","Kentucky","Louisiana","Maine","Maryland","Massachusetts","Michigan","Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada","New Hampshire","New Jersey","New Mexico","New York","North Carolina","North Dakota","Ohio","Oklahoma","Oregon","Pennsylvania","Rhode Island","South Carolina","South Dakota","Tennessee","Texas","Utah","Vermont","Virginia","Washington","West Virginia","Wisconsin","Wyoming")
    
       # Switch for State matching to org domains
    function StatesDomains ($state){
        Switch ($state){
        "Alabama" {$domains = @("state.al.us", "alabama.gov", "al.gov")}
        "Alaska" {$domains = @("state.ak.us", "alaska.gov", "ak.gov")}
        "Arizona" {$domains = @("state.az.us", "arizona.gov", "az.gov")}
        "Arkansas" {$domains = @("state.ar.us", "arkansas.gov", "ar.gov")}
        "California" {$domains = @("state.ca.us", "california.gov", "ca.gov")}
        "Colorado" {$domains = @("state.co.us", "colorado.gov", "co.gov")}
        "Connecticut" {$domains = @("state.ct.us", "ct.gov")}
        "Delaware" {$domains = @("state.de.us", "delaware.gov", "de.gov")}
        "Florida" {$domains = @("state.fl.us", "florida.gov", "fl.gov")}
        "Georgia" {$domains = @("state.ga.us", "georgia.gov", "ga.gov")}
        "Hawaii" {$domains = @("state.hi.us", "hawaii.gov", "ehawaii.gov", "hi.gov")}
        "Idaho" {$domains = @("state.id.us", "idaho.gov", "id.gov")}
        "Illinois" {$domains = @("state.il.us", "illinois.gov", "il.gov")}
        "Indiana" {$domains = @("state.in.us", "indiana.gov", "in.gov")}
        "Iowa" {$domains = @("state.ia.us", "iowa.gov", "ia.gov")}
        "Kansas" {$domains = @("state.ks.us", "kansas.gov", "ks.gov")}
        "Kentucky" {$domains = @("state.ky.us", "kentucky.gov", "ky.gov")}
        "Louisiana" {$domains = @("state.la.us", "louisiana.gov", "la.gov")}
        "Maine" {$domains = @("state.me.us", "maine.gov", "me.gov")}
        "Maryland" {$domains = @("state.md.us", "maryland.gov", "md.gov")}
        "Massachusetts" {$domains = @("state.ma.us", "mass.gov", "ma.gov", "massachusetts.gov")}
        "Michigan" {$domains = @("state.mi.us", "michigan.gov", "mi.gov")}
        "Minnesota" {$domains = @("state.mn.us", "mn.gov", "minnesota.gov")}
        "Mississippi" {$domains = @("state.ms.us", "mississippi.gov", "ms.gov")}
        "Missouri" {$domains = @("state.mo.us", "missouri.gov", "mo.gov")}
        "Montana" {$domains = @("state.mt.us", "montana.gov", "mt.gov")}
        "Nebraska" {$domains = @("state.ne.us", "nebraska.gov", "ne.gov")}
        "Nevada" {$domains = @("state.nv.us", "nevada.gov", "nv.gov")}
        "New Hampshire" {$domains = @("state.nh.us", "nh.gov","newhampshire.gov")}
        "New Jersey" {$domains = @("state.nj.us", "newjersey.gov", "nj.gov")}
        "New Mexico" {$domains = @("state.nm.us", "newmexico.gov", "nm.gov")}
        "New York" {$domains = @("state.ny.us", "ny.gov")}
        "North Carolina" {$domains = @("state.nc.us", "northcarolina.gov", "nc.gov")}
        "North Dakota" {$domains = @("state.nd.us", "northdakota.gov", "nd.gov")}
        "Ohio" {$domains = @("state.oh.us", "ohio.gov", "oh.gov")}
        "Oklahoma" {$domains = @("state.ok.us", "oklahoma.gov", "ok.gov")}
        "Oregon" {$domains = @("state.or.us", "oregon.gov", "or.gov")}
        "Pennsylvania" {$domains = @("state.pa.us", "pennsylvania.gov", "pa.gov")}
        "Rhode Island" {$domains = @("state.ri.us", "rhodeisland.gov", "ri.gov")}
        "South Carolina" {$domains = @("state.sc.us", "southcarolina.gov", "sc.gov")}
        "South Dakota" {$domains = @("state.sd.us", "sd.gov")}
        "Tennessee" {$domains = @("state.tn.us", "tennessee.gov", "tn.gov")}
        "Texas" {$domains = @("state.tx.us", "texas.gov", "tx.gov")}
        "Utah" {$domains = @("state.ut.us", "utah.gov")}
        "Vermont" {$domains = @("state.vt.us", "vermont.gov", "vt.gov")}
        "Virginia" {$domains = @("state.va.us", "virginia.gov")}
        "Washington" {$domains = @("state.wa.us", "washington.gov", "wa.gov")}
        "West Virginia" {$domains = @("state.wv.us", "wv.gov")}
        "Wisconsin" {$domains = @("state.wi.us", "wisconsin.gov", "wi.gov")}
        "Wyoming" {$domains = @("state.wy.us", "wyoming.gov", "wy.gov")}
        }
    
    return $domains
    }
    
    # Set export variable headers
    $expvar = @("State,Domain,DMARC")
    
    # Loop through states
    foreach($state in $states){
    	
    	$statedomains = StatesDomains($state)
    	
    	# Loop for domains
    	foreach($domain in $statedomains){
    		
    		# null DMARC variable every loop
    		$dmarc = $null
        
    		# Fetch DMARC record for current domain
    		$dmarc = Resolve-DnsName -Type TXT -Name "_dmarc.$domain" -errorvariable err -erroraction silentlycontinue
    		
    	    # If-else statement based on DMARC policy data. 
            # (Note: For the p=none case, I intentionally designed this to catch both p=none, and sp=none, as both are near equivocal in the lack of policy enforcement on a domain.)
            # This waterfall if evaluation in terms of policy checking is used in this script to filter from least strict, to most strict. 
            # For the use of this script, it also removes the need for a more complex regex type match. 
            # If any less-strict policy exists, that will be the reflected policy for the domain. Please also note this script does not do any syntax validation. 
      
    		if($dmarc -eq $null -or $dmarc.type -eq "SOA"){
    			write-host -foregroundcolor magenta $state - $domain - No DMARC record exists!
    			$expvar += $state + "," + $domain + "," + "norecord"
    		}
    		elseif($dmarc.strings -like "*p=none*"){
    			write-host -foregroundcolor red $state - $domain - $dmarc.strings
    			$expvar += $state + "," + $domain + "," + "none"
    		}
    		elseif($dmarc.strings -like "*p=quarantine*"){
    			write-host -foregroundcolor yellow $state - $domain - $dmarc.strings
    			$expvar += $state + "," + $domain + "," + "quarantine"
    		}
    		elseif($dmarc.strings -like "*p=reject*"){
    			write-host -foregroundcolor green $state - $domain - $dmarc.strings
    			$expvar += $state + "," + $domain + "," + "reject"
    		}			
    	}
    }
    	
    	# Hacky workaround to get the object data into a CSV format. 
        # Exports object data, re-imports using the import-csv method interpretation, and then finally exports as the final formatted CSV.
    	$expvar | Out-File $env:userprofile\desktop\tempcsv.csv
    	$tempvar = Import-Csv $env:userprofile\desktop\tempcsv.csv
    	$tempvar | Export-Csv $env:userprofile\desktop\stateDMARC.csv -NoTypeInformation
    	remove-item $env:userprofile\desktop\tempcsv.csv
