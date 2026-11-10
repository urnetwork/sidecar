// MAIL-M7-12's one-time codes on a synthetic corpus: the shapes sign-up and login mail use, in a few languages, and
// what looks like a code and is not, such as order numbers, dates, prices, phone numbers and ZIP codes. Every name,
// number and domain is synthetic.

package sidecar

import (
	"strings"
	"testing"
)

// Codes found, in the subject or the text.
func TestMailExtractOneTimeCodeFindsCodes(t *testing.T) {
	cases := []struct {
		subject string
		text    string
		want    string
	}{
		{subject: "Your Example verification code is 482913", want: "482913"},
		{subject: "482913 is your Example code", want: "482913"},
		{subject: "Welcome to Example", text: "Hello,\nYour verification code: 734 562\nIt expires in 10 minutes.", want: "734562"},
		{subject: "Sign in to Example", text: "Use this code to sign in: 905-118. Do not share it.", want: "905118"},
		{subject: "Example security code", text: "Your one-time passcode is 51837204.", want: "51837204"},
		{subject: "Confirm your email", text: "Enter the code below to verify your address:\n\nQ7KX29TZ\n", want: "Q7KX29TZ"},
		{subject: "Login", text: "Your OTP is 6620. Valid for 5 minutes.", want: "6620"},
		{subject: "Tu código de verificación", text: "Tu código es 274518.", want: "274518"},
		{subject: "Ваш код подтверждения", text: "Ваш код: 3381", want: "3381"},
		{subject: "验证码", text: "您的验证码：582014，5分钟内有效。", want: "582014"},
		{subject: "確認コード", text: "認証コード: 667120", want: "667120"},
		{subject: "Example", text: "Your code for order #551203 is 908877.", want: "908877"},
		{subject: "Verify your account", text: "Enter 119406 to verify your new device.", want: "119406"},
	}
	for _, c := range cases {
		if got := MailExtractOneTimeCode(c.subject, c.text); got != c.want {
			t.Errorf("%q / %q: %q, want %q", c.subject, c.text, got, c.want)
		}
	}
}

// What looks like a code and is not: nothing is found.
func TestMailExtractOneTimeCodeRefusesLookalikes(t *testing.T) {
	cases := []struct {
		subject string
		text    string
	}{
		{subject: "Your order 551203 has shipped", text: "Track your order #551203 with code-free returns."},
		{subject: "Invoice 2026-114", text: "Invoice number: 77812345. Use promo code SAVE2026X next time."},
		{subject: "Delivery update", text: "Your ZIP code 94105 is in our delivery area. Tracking 1Z999AA10123456784."},
		{subject: "Your code of conduct", text: "Code of conduct meeting on 11/09/2026 at 10:30 in room 4412."},
		{subject: "Verification", text: "Your verification is complete. Total charged: $1234 or 1234 USD on Nov 9, 2026."},
		{subject: "Security", text: "Your security code request: call 555-123-4567 or +1 555 123 4567 about your account."},
		{subject: "Release", text: "Code freeze: version 2026.11.0, built 20261109."},
		{subject: "Your coupon code", text: "Use coupon code 1234 at checkout."},
		{subject: "Copyright", text: "© 2026 Example. Your verification code will arrive in 2026."},
		{subject: "Plain mail", text: "No numbers here, just a note about the code we wrote."},
		{subject: "Ticket", text: "Your code is in ticket 448812."},
	}
	for _, c := range cases {
		if got := MailExtractOneTimeCode(c.subject, c.text); got != "" {
			t.Errorf("%q / %q: found %q", c.subject, c.text, got)
		}
	}
}

// The subject wins over the text, and what is not UTF-8 or too long breaks nothing.
func TestMailExtractOneTimeCodeOrderAndBounds(t *testing.T) {
	if got := MailExtractOneTimeCode("Your code is 111222", "Your code is 333444"); got != "111222" {
		t.Errorf("%q", got)
	}
	if got := MailExtractOneTimeCode("\xff\xfe code \xff 445566", ""); got != "445566" {
		t.Errorf("past invalid bytes: %q", got)
	}
	long := strings.Repeat("filler text ", 20000) + "your code is 778899"
	if got := MailExtractOneTimeCode("", long); got != "778899" {
		t.Errorf("deep in a long text: %q", got)
	}
	if got := MailExtractOneTimeCode("", "code "+strings.Repeat("9", 40)); got != "" {
		t.Errorf("a run past 8 digits: %q", got)
	}
}
