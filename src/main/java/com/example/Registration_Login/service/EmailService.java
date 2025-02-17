package com.example.Registration_Login.service;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final SendGrid sendGrid;

    public void sendOtpEmail(String to, String otp) {
        Email from = new Email("huyngps33320@fpt.edu.vn");
        String subject = "Your OTP Code";
        Email toEmail = new Email(to);
        Content content = new Content("text/plain", "Your OTP is: " + otp);
        Mail mail = new Mail(from, subject, toEmail, content);

        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sendGrid.api(request);
            System.out.println("SendGrid Response Status Code: " + response.getStatusCode());
        } catch (IOException ex) {
            throw new RuntimeException("Error sending email via SendGrid", ex);
        }
    }
}