Class HS.AWS.S3Upload Extends Ens.BusinessOperation
{

Parameter ADAPTER = "EnsLib.HTTP.OutboundAdapter";

Parameter INVOCATION = "Queue";

Property Region As %String;

Property Bucket As %String;

Property Host As %String;

Property UseProxy As %Boolean;

Parameter SETTINGS = "Region:Additional,Bucket:Additional,Host:Additional,UseProxy:Additional";

Method Upload(region As %String, host As %String, bucket As %String, key As %String, payload As %Library.GlobalCharacterStream, contentType As %String) As %String
{
	
	set endpoint = "https://"_host_"/"_bucket_"/"_key
	
	if '$IsObject(..Adapter.%CredentialsObj) do ..Adapter.CredentialsSet(..Adapter.Credentials)
	if '$IsObject(..Adapter.%CredentialsObj) {
		set tSC=$$$EnsError($$$EnsErrNoCredentials,..Adapter.Credentials) quit
	}
	set AWSAccessID=..Adapter.%CredentialsObj.Username, AWSSecretKey=..Adapter.%CredentialsObj.Password    
	
	// HTTPRequestMethod
	set method = "PUT"
	
	// CanonicalURI
	set uri = "/"_bucket_"/"_key
	
	// CanonicalQueryString
	set queryString = ""
	
	// RequestPayload hash
	set payload = payload.Read(3641144)
	set plh = $system.Encryption.SHAHash(256,$ZCONVERT(payload,"O","UTF8"))
	set plh = $ZCVT(##class(%xsd.hexBinary).LogicalToXSD(plh),"L")
	
	// CanonicalHeaders
	set date=..AmzDateTime()
	set fmtDate = $e(date,0,8)
	
	set headers = "content-length:"_$l(payload)_$c(10)
	set headers = headers_"host:"_host_$c(10)
	set headers = headers_"x-amz-content-sha256:"_plh_$c(10)
	set headers = headers_"x-amz-date:"_date_$c(10)
	
	// SignedHeaders
	set sh = "content-length;host;x-amz-content-sha256;x-amz-date"
	
	//Combine the request
	set cr = method_$c(10)
	set cr = cr_uri_$c(10) 
	set cr = cr_queryString_$c(10)
	set cr = cr_headers_$c(10)
	set cr = cr_sh_$c(10)
	set cr = cr_plh
	
	// Create digest
	set digest = $ZCONVERT(cr,"O","UTF8") 
	set digest = $System.Encryption.SHAHash(256,digest)
	set digest = $ZCVT(##class(%xsd.hexBinary).LogicalToXSD(digest),"L")
	
	// Create string to sign
	set algorithm  = "AWS4-HMAC-SHA256"
	set credScope  = $e(date,0,8)_"/"_region_"/s3/aws4_request"
	set signString = algorithm_$c(10)_date_$c(10)_credScope_$c(10)_digest
	
	// Calculate signature key
	set signingKey = ..getSignatureKey(AWSSecretKey,$e(date,0,8),region,"s3")
	
	// Calculate signature
	set sig = $System.Encryption.HMACSHA(256,signString,signingKey)
	set sig = $ZCVT(##class(%xsd.hexBinary).LogicalToXSD(sig),"L")
	
	// Send it to S3
	set https=##class(%Net.HttpRequest).%New()
	set https.Https=1
	set https.Server=host
	set https.SSLConfiguration=..Adapter.SSLConfig
	set https.Port=443
	set https.Timeout=30
	
	 if ..UseProxy {
 		set https.ProxyServer=..Adapter.ProxyServer
 		set https.ProxyPort=..Adapter.ProxyPort
 		set httos.ProxyHTTPS=..Adapter.ProxyHTTPS
 		set https.ProxyTunnel=1
 	}	
	
	set https.Authorization="AWS4-HMAC-SHA256 Credential="_AWSAccessID_"/"_credScope_", SignedHeaders="_sh_", Signature="_sig
	do https.SetHeader("x-amz-date",date)
	do https.SetHeader("x-amz-content-sha256",plh)
	do https.EntityBody.Write(payload)
	
	set url = "/"_bucket_"/"_key
	set tSC = https.Put(url)
	if https.HttpResponse.StatusCode'=200 {
		set tSC = $$$ERROR($$$GeneralError,https.HttpResponse.Data.Read())
	}
	
	quit tSC
}

ClassMethod AmzDateTime() As %String
{
	set dt=$TR($TR($P($ZDT($ZTS,3,,3),".",1),"-:TZ","")," ","T")_"Z"
	quit dt
}

ClassMethod getSignatureKey(secretKey, date, region, service) As %String
{
	set kDate = ..sign("AWS4"_secretKey, date)
	set kRegion = ..sign(kDate,region)
	set kService = ..sign(kRegion,service)
	set kSigning = ..sign(kService,"aws4_request")
	quit kSigning
}

ClassMethod sign(key, msg) As %String
{
	set sig=$system.Encryption.HMACSHA(256,msg,key)
	quit sig
}

Method UploadSDA(request As HS.AWS.Message.XmlContainer, response As Ens.StringResponse) As %Status
{
	set tSC=$$$OK
	
	if request.contentString'="" {
		do request.content.Write(request.contentString) 
		do request.content.Rewind()
	}
	
	if request.bucket'="" {
		set bucket=request.bucket
	} else {
		set bucket=..Bucket
	}
	
	set tSC = ..Upload(..Region, ..Host, bucket, request.key, request.content, "application/xml")
	
	set response=##class(Ens.StringResponse).%New()
	if tSC'=$$$OK {
		set response.StringValue=tSC
	} else {
		set response.StringValue="Success"
	}

	quit tSC
}

Method UploadJson(request As HS.AWS.Message.JsonContainer, response As Ens.StringResponse) As %Status
{
	set tSC=$$$OK
	
	if request.contentString'="" {
		do request.content.Write(request.contentString) 
		do request.content.Rewind()
	}
	
	if request.bucket'="" {
		set bucket=request.bucket
	} else {
		set bucket=..Bucket
	}
	
	set tSC = ..Upload(..Region, ..Host, bucket, request.key, request.content, "application/json")
	
	set response=##class(Ens.StringResponse).%New()
	if tSC'=$$$OK {
		set response.StringValue=tSC
	} else {
		set response.StringValue="Success"
	}
	
	quit tSC
}

XData MessageMap
{
<MapItems>
 <MapItem MessageType="HS.AWS.Message.XmlContainer">
    <Method>UploadSDA</Method>
  </MapItem>
   <MapItem MessageType="HS.AWS.Message.JsonContainer">
    <Method>UploadJson</Method>
  </MapItem>
</MapItems>
}

}
