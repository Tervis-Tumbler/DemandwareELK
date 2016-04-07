input {
    file {
        #path => "C:/Users/username/Desktop/DemandwareLogs/error-*.log"
        path => "$LogstashFilePathValue"
        type => "DemandwareCustom-Int_Bronto"
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
    }
    date {
        match => ["demandware_timestamp", "YYYY-MM-dd HH:mm:ss.SSS"]
        timezone => "UTC"
    }
    
    grok {
        match => { "path" => "^.*[\/\\](?<FileNameWithoutExtension>.*)\.(.*)$" }    
    }
    
    grok {
        match => { "FileNameWithoutExtension" => "\A(?<LogFileType>custom-int_bronto)-(?<LogFileBlade>[[:alpha:]]+[[:digit:]]-[[:digit:]])-%{WORD:LogFileBladeRole}-%{YEAR:LogFileYear}%{MONTHNUM:LogFileMonth}%{MONTHDAY:LogFileDay}"}
    }
    
    mutate {
        add_field => {"MessageHash" => "%{message}"}
    }
    
    grok {
        break_on_match => false
        match => [ "message", "\A%{SYSLOG5424SD} %{WORD:LoggerLevel} (?<ThreadName>[^|]+)\|(?<ThreadID>[^|]+)\|(?<NiceName>[^|]+)\|%{NOTSPACE:CodeName} %{NOTSPACE:ClassAndMethod}%{SPACE}%{GREEDYDATA:InterfaceMessage}" ]
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
        index => "logstash-demandware-custom-int_bronto-%{+YYYY.MM}"
        document_id => "%{MessageHash}"
    }
"@
}
)
}