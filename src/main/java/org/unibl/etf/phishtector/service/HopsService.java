package org.unibl.etf.phishtector.service;

import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.mail.internet.MailDateFormat;
import lombok.RequiredArgsConstructor;
import org.apache.james.mime4j.stream.Field;
import org.springframework.stereotype.Service;
import org.unibl.etf.phishtector.model.Hop;

@Service
@RequiredArgsConstructor
public class HopsService {

  private final IPService ipService;

  public List<Hop> parseHopsFromReceivedFields(List<Field> fields) {
    Pattern receivedPattern = Pattern.compile("(?:(Received:)|\\G(?!\\A))" +
        "\\s*(from|by|with|id|via|for|;)" +
        "\\s*(\\S+?(?:\\s+\\S+?)*?)\\s*" +
        "(?=Received:|by|with|id|via|for|;|\\z)");

    LinkedList<Hop> hops = new LinkedList<>();
    MailDateFormat mailDateFormat = new MailDateFormat();
    fields.stream().filter(field -> field.getName().equals("Received")).forEach(field -> {
      try {
        processHop(field, receivedPattern, mailDateFormat, hops);
      } catch (ParseException e) {
        e.printStackTrace();
      }
    });
    return hops;
  }

  public void investigateHops(List<Hop> hops){
    hops.forEach(hop -> {
      if(hop.getFrom() != null) {
        hop.setIpAnalysisResponse(ipService.investigateIPAddress(hop));
        hop.setBlacklisted(ipService.checkBlacklistForIPAddress(hop).isBlacklisted());
      }else hop.setIpAnalysisResponse(null);
    });
  }

  private void processHop(Field field, Pattern pattern, MailDateFormat mailDateFormat,
      LinkedList<Hop> hops)
      throws ParseException {
    Matcher m = pattern.matcher(field.toString());

    Hop hop = new Hop();

    while (m.find()) {

      switch (m.group(2)) {
        case "with" -> {
          hop.setWith(m.group(3));
        }
        case "by" -> {
          hop.setBy(m.group(3));
        }
        case "from" -> {
          hop.setFrom(m.group(3));
        }
        case ";" -> {
          Date dateTime = mailDateFormat.parse(m.group(3));
          hop.setDateTime(dateTime);
        }
      }

    }
    if (!hops.isEmpty()) {
      Hop previous = hops.getFirst();
      previous.setDelay(
          Duration.ofMillis(previous.getDateTime().getTime() - hop.getDateTime().getTime()));
    }
    hops.addFirst(hop);
  }

}
