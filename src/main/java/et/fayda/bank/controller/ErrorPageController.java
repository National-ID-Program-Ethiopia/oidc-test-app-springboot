package et.fayda.bank.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Replaces Spring Boot's Whitelabel page. Every uncaught exception and HTTP error (404, 403, 500, ...)
 * is forwarded here and rendered with the same title/message/hint/detail shape as login errors.
 */
@Controller
public class ErrorPageController implements ErrorController {

    @RequestMapping("/error")
    public String error(HttpServletRequest request, HttpServletResponse response, Model model) {
        int status = statusOf(request);
        Throwable exception = (Throwable) request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        String path = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        String servletMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

        HttpStatus httpStatus = HttpStatus.resolve(status);
        String reason = httpStatus != null ? httpStatus.getReasonPhrase() : "Error";

        String title;
        String hint;
        switch (status) {
            case 400 -> {
                title = "Bad request";
                hint = "The request was malformed. Go back and try again.";
            }
            case 401 -> {
                title = "Sign in required";
                hint = "Your session has ended. Sign in with Fayda again.";
            }
            case 403 -> {
                title = "Access denied";
                hint = "Your session may have expired, or the form was submitted from a stale page. Sign in again.";
            }
            case 404 -> {
                title = "Page not found";
                hint = "Check the address, or go back to the dashboard.";
            }
            case 405 -> {
                title = "Method not allowed";
                hint = "This page does not accept that kind of request.";
            }
            default -> {
                title = status >= 500 ? "Something went wrong" : reason;
                hint = status >= 500 ? "This is a server-side error; the full exception is logged in the server console." : null;
            }
        }

        Throwable root = rootCause(exception);
        String message = root != null && root.getMessage() != null ? root.getMessage()
                : servletMessage != null && !servletMessage.isBlank() ? servletMessage
                : reason;

        if (exception != null) {
            System.out.println("========== REQUEST FAILED (" + status + " " + path + ") ==========");
            exception.printStackTrace();
        }

        response.setStatus(status);
        model.addAttribute("status", status);
        model.addAttribute("title", title);
        model.addAttribute("message", message);
        model.addAttribute("hint", hint);
        model.addAttribute("detail", diagnostic(status, reason, path, exception));
        return "error";
    }

    private static int statusOf(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        return status instanceof Integer code ? code : HttpStatus.INTERNAL_SERVER_ERROR.value();
    }

    private static Throwable rootCause(Throwable exception) {
        Throwable root = exception;
        while (root != null && root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root;
    }

    private static String diagnostic(int status, String reason, String path, Throwable exception) {
        StringBuilder detail = new StringBuilder()
                .append("HTTP ").append(status).append(' ').append(reason)
                .append("\npath=").append(path);
        for (Throwable t = exception; t != null; t = t.getCause() == t ? null : t.getCause()) {
            detail.append(t == exception ? "\n" : "\ncaused by: ")
                    .append(t.getClass().getName()).append(": ").append(t.getMessage());
        }
        return detail.toString();
    }
}
