input {
    file {
        path => "$LogstashFilePathValue"
        type => "DemandwareJobs"
        tags => "$EnvironmentName"
        start_position => "beginning"
        ignore_older => 99999999
        sincedb_path => "NUL"
        codec => multiline {
            pattern => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]"
            negate => true
            what => previous
            auto_flush_interval => 10
            max_lines => 9999
        }
    }
}

filter {
    grok {
        match => { "message" => "\A\[%{TIMESTAMP_ISO8601:demandware_timestamp} GMT\]" }
        tag_on_failure => ["demandware_timestamp_grokparsefailure"]
    }
    date {
        match => ["demandware_timestamp", "YYYY-MM-dd HH:mm:ss.SSS"]
        timezone => "UTC"
    }
    
    grok {
        match => { "path" => "^.*[\/\\](?<FileNameWithoutExtension>.*)\.(.*)$" }
        tag_on_failure => ["FileNameWithoutExtension_grokparsefailure"]
    }
    
    grok {
        match => { "FileNameWithoutExtension" => "\A%{WORD:LogFileType}-(?<LogFileBlade>[[:alpha:]]+[[:digit:]]-[[:digit:]])-%{WORD:LogFileBladeRole}-%{YEAR:LogFileYear}%{MONTHNUM:LogFileMonth}%{MONTHDAY:LogFileDay}"}
        tag_on_failure => ["FileNameWithoutExtensionProperties_grokparsefailure"]

    }
    
    mutate {
        add_field => {"MessageHash" => "%{message}"}
    }
    
    grok {
        #break_on_match => false
        match => [ "message", "\A%{SYSLOG5424SD} Created Job configuration for Schedule \[%{CISCO_REASON:ScheduleName}, %{WORD:ScheduleID}]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Created Job configuration for domain \[%{CISCO_REASON:DomainName}]\. Job type \[%{BASE10NUM:JobTypeNumber}]\. Job Configuration \[, %{WORD:JobConfigurationID}]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Started executing job pipeline\. Schedule \[%{CISCO_REASON:ScheduleName}, %{WORD:ScheduleID}]\. Job configuration \[%{CISCO_REASON:JobConfigurationName}, %{WORD:JobConfigurationID}]\. Domain \[%{CISCO_REASON:DomainName}]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{CISCO_REASON:ScheduleName}, %{WORD:ScheduleID}, %{WORD:JobConfigurationID}, %{PROG:sitename}] has \[%{BASE10NUM:NumberOfResourcesAssociatedWithJob}] resources associated with it\. ThreadId \[%{WORD:ThreadName}\|%{BASE10NUM:ThreadID}\|%{CISCO_REASON:NiceName}\|%{PROG:CodeName}\[%{BASE10NUM:NumberAfterCodeName}]]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{CISCO_REASON:ScheduleName}, %{WORD:JobConfigurationID}, %{CISCO_REASON:sitename}] Execute pipeline\. PipeLine: %{JAVAFILE}, ThreadId: %{CISCO_REASON:ThreadName}\|%{BASE10NUM:ThreadID}\|%{CISCO_REASON:NiceName}\|%{JAVAFILE:CodeName}\[%{BASE10NUM:NumberAfterCodeName}], User: %{WORD:UserName}" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{CISCO_REASON:ScheduleName}, %{WORD:JobConfigurationID}, %{CISCO_REASON:sitename}] Done executing pipeline\. PipeLine: %{JAVAFILE}, ThreadId: %{CISCO_REASON:ThreadName}\|%{BASE10NUM:ThreadID}\|%{CISCO_REASON:NiceName}\|%{JAVAFILE:CodeName}\[%{BASE10NUM:NumberAfterCodeName}]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{CISCO_REASON:ScheduleName}, %{WORD:JobConfigurationID}, %{CISCO_REASON:sitename}] total execution time %{BASE10NUM:TotalJobExecutionTime} ms\." ]
        tag_on_failure => ["JobContent_grokparsefailure"]
    }
    
    mutate {
        convert => { "TotalJobExecutionTime" => "integer" }
    }
    
    anonymize {
        algorithm => "SHA1"
        fields => ["MessageHash"]
        key => ""
    }
}
output {
$(
if ($Development) {@"
    stdout { codec => rubydebug }
"@
} else { @"
    elasticsearch {
        hosts => localhost
        index => "logstash-demandware-jobs-%{+YYYY.MM}"
        document_id => "%{MessageHash}"
    }
"@
}
)
}