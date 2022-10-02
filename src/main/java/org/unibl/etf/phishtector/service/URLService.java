package org.unibl.etf.phishtector.service;

import com.linkedin.urls.Url;
import com.linkedin.urls.detection.UrlDetector;
import com.linkedin.urls.detection.UrlDetectorOptions;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.apache.commons.mail.util.MimeMessageParser;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.unibl.etf.phishtector.config.ApiProperties;
import org.unibl.etf.phishtector.request.GoogleSafeBrowsingRequest;
import org.unibl.etf.phishtector.request.ThreatEntry;
import org.unibl.etf.phishtector.request.ThreatInfo;
import org.unibl.etf.phishtector.response.googleSafeBrowsing.GoogleSafeBrowsingResponse;
import org.unibl.etf.phishtector.response.googleSafeBrowsing.Matches;
import org.unibl.etf.phishtector.response.url.URLResponse;

@Service
@RequiredArgsConstructor
public class URLService {

  private final RestTemplate restTemplate;
  private final ApiProperties apiProperties;

  public URLResponse analyzeMailUrls(MimeMessage mimeMessage){
    URLResponse urlResponse = new URLResponse();
    try {
      Set<Url> parsedUrls = parseUrls(mimeMessage);
      List<GoogleSafeBrowsingResponse> urlBackListMatches = checkURLsReputation(
          parsedUrls).getMatches();

      if (urlBackListMatches != null) {
        List<String> urlBlackListMatchesString =
            urlBackListMatches.stream().map(url -> url.getThreat().getUrl()).toList();
        parsedUrls.removeIf(url -> urlBlackListMatchesString.contains(url.getFullUrl()));
      }else urlBackListMatches = Collections.emptyList();
      urlResponse.setValidUrls(parsedUrls.stream().map(Url::getFullUrl).toList());
      urlResponse.setBlacklistedUrls(urlBackListMatches);
    } catch (Exception e) {
      urlResponse.setExceptionMessage("An error occurred while analyzing urls.");
      e.printStackTrace();
    }
    return urlResponse;
  }

  private Set<Url> parseUrls(MimeMessage mimeMessage) throws Exception {
    Set<Url> urlSet = new HashSet<>();
    MimeMessageParser mimeMessageParser = new MimeMessageParser(mimeMessage).parse();
    if (mimeMessageParser.hasPlainContent()) {
      UrlDetector plainTextParser = new UrlDetector(mimeMessageParser.getPlainContent(),
          UrlDetectorOptions.Default);
      urlSet.addAll(plainTextParser.detect());

    }
    if (mimeMessageParser.hasHtmlContent()) {
      UrlDetector htmlParser = new UrlDetector(mimeMessageParser.getHtmlContent(),
          UrlDetectorOptions.HTML);
      urlSet.addAll(htmlParser.detect());
    }
    return urlSet;
  }

  private Matches checkURLsReputation(Set<Url> urls) {

    ThreatInfo threatInfo = ThreatInfo.builder()
        .threatTypes(Arrays.asList(
            "MALWARE",
            "SOCIAL_ENGINEERING"))
        .platformTypes(List.of("ANY_PLATFORM"))
        .threatEntryTypes(List.of("URL"))
        .threatEntries(
            urls.stream().map(url -> new ThreatEntry(url.getFullUrl())).toList())
        .build();
    GoogleSafeBrowsingRequest googleSafeBrowsingRequest =
        GoogleSafeBrowsingRequest.builder()
            .threatInfo(threatInfo).build();

    return restTemplate.postForEntity(apiProperties.getGoogleSafeBrowsing(),
        googleSafeBrowsingRequest, Matches.class).getBody();
  }


}
