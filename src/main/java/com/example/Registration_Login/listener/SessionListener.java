package com.example.Registration_Login.listener;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.util.logging.Logger;

public class SessionListener implements HttpSessionListener {

    private static final Logger logger = Logger.getLogger(SessionListener.class.getName());

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        logger.info("Session created: " + event.getSession().getId());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        logger.info("Session destroyed (timeout): " + event.getSession().getId());
    }
}
