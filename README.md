
# Trigrams URL detection. 

This query will hep you finld URL's that are not in the top 1m websites aroubnd the world. 

## Query

```
let triThreshold = 10000;
let querystarttime = 24h;
let dgaLengthThreshold = 8;
let MDEDeviceNetworkEvents=(DeviceNetworkEvents
//| where DeviceName == "vm-secvictim01" and isnotempty(RemoteUrl)
| where isnotempty(RemoteUrl)
| project DeviceName, RemoteUrl,RemoteIP,LocalIP,TimeGenerated);
let top1M = (externaldata (Position:int, Domain:string) [@"https://raw.githubusercontent.com/maheshmarthi/maheshmarthi/main/top-1m.csv.zip"] with (format="csv", zipPattern="*.csv"));
// extract tri grams that are above our threshold - i.e. are common
let triBaseline = top1M
| extend Domain = tolower(extract("([^.]*).{0,7}$", 1, Domain))
| extend AllTriGrams = array_concat(extract_all("(...)", Domain), extract_all("(...)", substring(Domain, 1)), extract_all("(...)", substring(Domain, 2)))
| mvexpand Trigram=AllTriGrams
| summarize triCount=count() by tostring(Trigram)
| sort by triCount desc
| where triCount > triThreshold
| distinct Trigram;
// collect domain information from common security log, filter and extract the DGA candidate and its trigrams
let allDataSummarized = MDEDeviceNetworkEvents
| where TimeGenerated > ago(querystarttime)
| extend Name = tolower(RemoteUrl)
| distinct Name
| where Name has "."
| where Name !endswith ".home" and Name !endswith ".lan"
// extract DGA candidate
| extend DGADomain = extract("([^.]*).{0,7}$", 1, Name)
| where strlen(DGADomain) > dgaLengthThreshold
// throw out domains with number in them
| where DGADomain matches regex "^[A-Za-z]{0,}$"
// extract the tri grams from summarized data
| extend AllTriGrams = array_concat(extract_all("(...)", DGADomain), extract_all("(...)", substring(DGADomain, 1)), extract_all("(...)", substring(DGADomain, 2)));
// throw out domains that have repeating tri's and/or >=3 repeating letters
let nonRepeatingTris = allDataSummarized
| join kind=leftanti
(
allDataSummarized
| mvexpand AllTriGrams
| summarize count() by tostring(AllTriGrams), DGADomain
| where count_ > 1
| distinct DGADomain
)
on DGADomain;
// find domains that do not have a common tri in the baseline
let dataWithRareTris = nonRepeatingTris
| join kind=leftanti
(
nonRepeatingTris
| mvexpand AllTriGrams
| extend Trigram = tostring(AllTriGrams)
| distinct Trigram, DGADomain
| join kind=inner
(
triBaseline
)
on Trigram
| distinct DGADomain
)
on DGADomain;
dataWithRareTris
// join DGAs back on connection data
| join kind=inner
(
MDEDeviceNetworkEvents
| where TimeGenerated > ago(querystarttime)
| extend DestinationHostName = tolower(RemoteUrl)
| extend DataSource=DeviceName
| project-rename Name=DestinationHostName
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by Name,LocalIP, RemoteIP, DataSource
)
on Name
| project StartTime, EndTime, Name, DGADomain, LocalIP, RemoteIP, DataSource


```
