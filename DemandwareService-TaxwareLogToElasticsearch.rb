input {
    file {
        path => "$LogstashFilePathValue"
        type => "DemandwareService-Taxware"
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
        match => { "FileNameWithoutExtension" => "\A(?<LogFileType>service-Taxware)-(?<LogFileBlade>[[:alpha:]]+[[:digit:]]-[[:digit:]])-%{WORD:LogFileBladeRole}-%{YEAR:LogFileYear}%{MONTHNUM:LogFileMonth}%{MONTHDAY:LogFileDay}"}
    }
    
    mutate {
        add_field => {"MessageHash" => "%{message}"}
    }
    
    grok {
        break_on_match => false
        match => [ "message", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass}\s\s\-\s%{DATA:sitename}\s%{WORD:ExceptionType}\s%{WORD:storefront}\s%{DATA:sessionid}\s%{DATA:random}\s%{DATA:alsorandom}\s%{GREEDYDATA:short_message}" ]
        match => [ "message", "\[[0-9\:\s\.\-A-Z]+\]\s%{WORD:LoggerLevel}\s%{WORD:servlet}\|%{NUMBER:idk}\|%{DATA:sitename}\|%{DATA:action}\|%{WORD:pipeline}\|%{DATA:sessionid} %{DATA:ExceptionClass} %{GREEDYDATA:short_message}" ]
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
        index => "logstash-demandware-service-taxware-%{+YYYY.MM}"
        document_id => "%{MessageHash}"
    }
"@
}
)
}