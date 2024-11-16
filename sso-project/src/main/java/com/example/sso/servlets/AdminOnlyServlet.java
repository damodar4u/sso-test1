package com.example.sso.servlets;

import javax.servlet.http.*;
import java.io.IOException;

public class AdminOnlyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Check user role
        String userRole = (String) request.getSession().getAttribute("userRole");

        if ("PrivilegedAdmin".equals(userRole)) {
            response.setContentType("text/html");
            response.getWriter().println("<h1>Welcome to the Admin-Only Page!</h1>");
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().println("<h1>Access Denied</h1>");
        }
    }
}
