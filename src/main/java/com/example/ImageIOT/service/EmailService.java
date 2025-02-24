package com.example.ImageIOT.service;

import com.example.ImageIOT.exception.CustomException;
import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final SendGrid sendGrid;

    @Value("${email.from}")
    private String emailFrom;

    @Value("classpath:templates/sendmail.html")
    private Resource emailTemplate;

    public void sendOtpEmail(String to, String otp) {
        Email from = new Email(emailFrom);
        String subject = "Your OTP Code";
        Email toEmail = new Email(to);

        String htmlContent;
        try {
            htmlContent = StreamUtils.copyToString(emailTemplate.getInputStream(), StandardCharsets.UTF_8);
            htmlContent = htmlContent.replace("{{otp}}", otp);
        } catch (IOException e) {
            throw new CustomException("Error loading email template: " + e.getMessage(), 500);
        }

        Content content = new Content("text/html", htmlContent);
        Mail mail = new Mail(from, subject, toEmail, content);

        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sendGrid.api(request);
            System.out.println("SendGrid Response Status Code: " + response.getStatusCode());
        } catch (IOException ex) {
            throw new CustomException("Error sending email via SendGrid: " + ex.getMessage(), 500);
        }
    }
}
