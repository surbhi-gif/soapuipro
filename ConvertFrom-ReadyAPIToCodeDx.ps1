<#
.SYNOPSIS
Converts a Ready API XML report to a Code Dx report for importing results.

.DESCRIPTION
Used to convert a Ready API XML report file to a Code Dx XML format so it can be imported.  
 
.EXAMPLE
ConvertFrom-ReadyAPIToCodeDx [scan_file_to_process] [target_endpoint] [output_directory]
#>
    
#Function ConvertFrom-ReadyAPIToCodeDX
#{
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceScanFilepath,
        [Parameter(Mandatory=$true)]
        [string]$TargetEndPoint,
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )
    
    #Setup variables
    $CDate = Get-Date -format "yyyy-MM-dd-HHmmss"
    $OutputFilePath = $OutputDir.Trim("""") + "\RA2CDX-" + $CDate + ".xml"
    
    #Enable for Debugging
    #
    #$SourceScanFilepath = "ReadyAPI_sample.xml"
    #$OutputFilePath = "C:\Users\aacuna\Documents\repos\powershell\Code Dx\RA2CDX-" + $CDate + ".xml"
    
    $SourceScanFile = $SourceScanFilepath.Trim("""")
    $ToolName = "ReadyAPI"
    $cwe
    $description
    $location = $TargetEndPoint
    $reportDate
    $mdtags = @("duration","start","end","status")
    $mdname
    $mdvalue

    #Setup Code Dx output doc
    [xml]$doc = New-Object System.Xml.XmlDocument
    $dec = $doc.CreateXmlDeclaration("1.0","UTF-8",$null)
    $updateXML= $doc.AppendChild($dec)
    $reportComment = "ReadyAPI to Code Dx - Generated $CDate"
    $updateXML= $doc.AppendChild($doc.CreateComment($reportComment))
    $root = $doc.CreateNode("element","report",$null)
    
    #read source ThunderScan file and create custom PSO
    [xml]$SourceScanData = Get-Content -Encoding UTF8 -Raw -Path $SourceScanFile

    #pull report date attributes and reformat for Code Dx file
    $reportDate = $CDate.Substring(0,10)

    #Set Root attributes
    $root.SetAttribute("date",$reportDate)
    $root.SetAttribute("tool",$ToolName)

    #create findings Element
    $fds = $doc.CreateNode("element","findings",$null)

    #Get child nodes of results
    $Results = $SourceScanData.securityScanRequest.securityScanResult.securityScanResults.ChildNodes

    Foreach($result in $Results){
        If($result.status -eq "FAIL"){
            $fd = $doc.CreateNode("element","finding",$null)
            #$cwe = $doc.CreateNode("element","cwe",$null)
            $desc = $doc.CreateNode("element","description",$null)
            $tl = $doc.CreateNode("element","tool",$null)
            $loc = $doc.CreateNode("element","location",$null)
            $md = $doc.CreateNode("element","metadata",$null)

            #Set finding "fd" attributes
            $fd.SetAttribute("severity", "critical")
            $fd.SetAttribute("type","dynamic")
            $fd.SetAttribute("status", "new")

            #Set CWE attributes
            #$cwe.SetAttribute("id", $result.cwe.SubString(4))

            #build location node and attributes
            $loc.SetAttribute("type","url")
            $loc.SetAttribute("path", $location)

            #Set Tool attributes
            $tl.SetAttribute("name",$ToolName)
            $tl.SetAttribute("category","Security")
            $tl.SetAttribute("code", $result.name)

            #Set description attributes
            $desc.SetAttribute("format", "plain-text")
			$descText = $result.log.'#cdata-section'
			if ($descText -eq $null) {
				$descText = $result.log
			}
            $desc.InnerText = $descText

            #Capture current vuln object for use later
            $vo = $result

            #Build the Metadata Node
            $mdtags | forEach {
                $e = $doc.CreateNode("element","value",$null)
                $e.SetAttribute("key",$_)
                $e.InnerText = $vo.$_
                $updateXML= $md.AppendChild($e)
            }

            #append remaining children to finding
            #$updateXML= $fd.AppendChild($cwe)
            $updateXML= $fd.AppendChild($tl)
            $updateXML= $fd.AppendChild($loc)
            $updateXML= $fd.AppendChild($desc)
            $updateXML= $fd.AppendChild($md)

            #append finding to findings
            $updateXML= $fds.AppendChild($fd)
        }
    }

    $updateXML= $root.AppendChild($fds)
    $updateXML= $doc.AppendChild($root) | Out-Null
    Write-Host "Outputing file to:  $OutputFilePath"
    $doc.Save($OutputFilePath)
#}