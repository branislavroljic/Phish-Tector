package org.unibl.etf.phishtector.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "mail.api")
public class ApiProperties {
  private String googleSafeBrowsing;
  private String techniknews;
  private String ipblacklist;
  private String ipblacklistKey;

}
