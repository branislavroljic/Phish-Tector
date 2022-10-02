package org.unibl.etf.phishtector.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "mail.header")
public class MailHeaderProperties {

  private String dmarcPrefix;
  private String dmarcAspfRelaxed;
  private String dmarcAspfStrict;
  private String spfVersion;
}
