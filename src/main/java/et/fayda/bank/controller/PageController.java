package et.fayda.bank.controller;

import et.fayda.bank.config.LoginError;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class PageController {

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        // Shown once: the failure handler stores it, the next home page view consumes it.
        Object loginError = session.getAttribute(LoginError.SESSION_KEY);
        if (loginError != null) {
            session.removeAttribute(LoginError.SESSION_KEY);
            model.addAttribute("loginError", loginError);
        }
        return "home";
    }

    /** First page after a Fayda login: the verified userinfo, then on to the dashboard (as the Django app's callback view). */
    @GetMapping("/welcome")
    public String welcome(@AuthenticationPrincipal OidcUser user, Model model) {
        addUserAttributes(model, user);
        return "callback";
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OidcUser user, Model model) {
        addUserAttributes(model, user);
        return "dashboard";
    }

    @GetMapping("/unverified-dashboard")
    public String unverifiedDashboard(Model model) {
        model.addAttribute("userName", "User");
        return "unverified_dashboard";
    }

    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OidcUser user, Model model) {
        addUserAttributes(model, user);
        return "profile";
    }

    @GetMapping("/account-verification")
    public String accountVerification() {
        return "account_verification";
    }

    @GetMapping("/loan-eligibility")
    public String loanEligibility() {
        return "loan_eligibility";
    }

    @GetMapping("/account-balance")
    public String accountBalance() {
        return "account_balance";
    }

    @GetMapping("/transactions")
    public String transactions() {
        return "transactions";
    }

    @GetMapping("/exchange-rates")
    public String exchangeRates() {
        return "exchange_rates";
    }

    @GetMapping("/coming-soon")
    public String comingSoon() {
        return "coming_soon";
    }

    private void addUserAttributes(Model model, OidcUser user) {
        if (user == null || user.getUserInfo() == null) {
            return;
        }
        var info = user.getUserInfo();
        model.addAttribute("name",            str(info.getClaim("name")));
        model.addAttribute("email",           str(info.getClaim("email")));
        model.addAttribute("phone",           str(info.getClaim("phone_number")));
        model.addAttribute("gender",          str(info.getClaim("gender")));
        model.addAttribute("birthdate",       str(info.getClaim("birthdate")));
        model.addAttribute("residenceStatus", str(info.getClaim("nationality")));
        model.addAttribute("address",         str(info.getClaim("address")));
        model.addAttribute("userPicture",     str(info.getClaim("picture")));
        model.addAttribute("sub",             user.getSubject());
    }

    private String str(Object value) {
        // OIDC "address" is a JSON object; show its formatted form (or its parts) rather than a Map's toString().
        if (value instanceof Map<?, ?> map) {
            Object formatted = map.get("formatted");
            if (formatted != null) {
                return formatted.toString();
            }
            return map.values().stream()
                    .filter(v -> v != null && !v.toString().isBlank())
                    .map(Object::toString)
                    .collect(Collectors.joining(", "));
        }
        return value != null ? value.toString() : "";
    }
}