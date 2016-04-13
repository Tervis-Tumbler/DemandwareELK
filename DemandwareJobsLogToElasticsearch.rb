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
        match => [ "message", "\A%{SYSLOG5424SD} Created Job configuration for Schedule \[%{NOTCOMMA:ScheduleName}, %{NOTBRACKET:ScheduleID}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Created Job configuration for domain \[%{NOTBRACKET:DomainName}\]\. Job type \[%{BASE10NUM:JobTypeNumber}\]\. Job Configuration \[, %{NOTBRACKET:JobConfigurationID}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Started executing job pipeline\. Schedule \[%{NOTCOMMA:ScheduleName}, %{WORD:ScheduleID}\]\. Job configuration \[%{NOTCOMMA:JobConfigurationName}, %{NOTBRACKET:JobConfigurationID}\]\. Domain \[%{NOTBRACKET:DomainName}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} I will not run schedule \[%{NOTCOMMA:ScheduleName}, %{NOTBRACKET:JobConfigurationID}\]\. Reason \[%{NOTBRACKET:ReasonForNotRunningSchedule}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{NOTCOMMA:ScheduleName}, %{NOTCOMMA:ScheduleID}, %{NOTCOMMA:JobConfigurationID}, %{NOTBRACKET:sitename}\] has \[%{BASE10NUM:NumberOfResourcesAssociatedWithJob}\] resources associated with it\. ThreadId \[%{NOTPIPE:ThreadName}\|%{BASE10NUM:ThreadID}\|%{NOTPIPE:NiceName}\|%{NOTBRACKET:CodeName}\[%{BASE10NUM:NumberAfterCodeName}\]\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{NOTCOMMA:JobConfigurationName}, %{NOTCOMMA:JobConfigurationID}, %{NOTBRACKET:sitename}\] Execute pipeline\. PipeLine: %{NOTCOMMA:PipeLineName}, ThreadId: %{NOTPIPE:ThreadName}\|%{BASE10NUM:ThreadID}\|%{NOTPIPE:NiceName}\|%{NOTBRACKET:CodeName}\[%{BASE10NUM:NumberAfterCodeName}\], User: %{WORD:UserName}" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{NOTCOMMA:JobConfigurationName}, %{NOTCOMMA:JobConfigurationID}, %{NOTBRACKET:sitename}\] Done executing pipeline\. PipeLine: %{NOTCOMMA:PipeLineName}, ThreadId: %{NOTPIPE:ThreadName}\|%{BASE10NUM:ThreadID}\|%{NOTPIPE:NiceName}\|%{NOTBRACKET:CodeName}\[%{BASE10NUM:NumberAfterCodeName}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{NOTCOMMA:JobConfigurationName}, %{NOTCOMMA:JobConfigurationID}, %{NOTBRACKET:sitename}\] total execution time %{BASE10NUM:TotalJobExecutionTime} ms\." ]
        match => [ "message", "\A%{SYSLOG5424SD} Job \[%{NOTCOMMA:ScheduleName}, %{NOTBRACKET:ScheduleID}\], Submitting Job Schedule for execution. ThreadId \[%{NOTBRACKET:ThreadName}\[%{BASE10NUM:NumberAfterThreadName}\]\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Monitor could not be locked for Job \[%{NOTCOMMA:ScheduleName}, %{NOTBRACKET:JobConfigurationID}\]\. ThreadId: %{NOTPIPE:ThreadName}\|%{BASE10NUM:ThreadID}\[%{BASE10NUM:NumberAfterThreadID}\]" ]
        match => [ "message", "\A%{SYSLOG5424SD} Hung job detection. Job \[%{NOTCOMMA:ScheduleName}, %{NOTBRACKET:ScheduleID}\] does not appear to hang. Action \[%{NOTBRACKET:Action}\]" ]
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