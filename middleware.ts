import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET
);

// 1. הגדרת נתיבים ציבוריים שלא דורשים להתחבר
const PUBLIC_PATHS = ["/login", "/register", "/forgot-password", "/api/auth"];

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Redirect uppercase URLs to lowercase (SEO canonical normalization)
  const lower = pathname.toLowerCase();
  if (pathname !== lower) {
    const url = req.nextUrl.clone();
    url.pathname = lower;
    return NextResponse.redirect(url, { status: 301 });
  }

  // 2. בדיקה אם הנתיב הנוכחי הוא נתיב ציבורי
  const isPublicPath = PUBLIC_PATHS.some((path) => pathname.startsWith(path));

  const token = req.cookies.get("auth_token")?.value;

  // 3. אם אין טוקן והנתיב אינו ציבורי - רק אז נבצע הפניה ל-login
  if (!token) {
    if (isPublicPath) {
      return NextResponse.next(); // מאפשר גישה חופשית ל-login/register
    }

    const url = new URL("/login", req.url);
    url.searchParams.set("from", pathname);
    return NextResponse.redirect(url);
  }

  // 4. אם המשתמש כבר מחובר (יש טוקן) ומנסה להיכנס ל-login, נעביר אותו לאזור האישי
  if (isPublicPath && token) {
    try {
      const { payload } = await jwtVerify(token, JWT_SECRET);
      const role = payload.role as string;
      const destination = role === "ADMIN" ? "/admin" : role === "PRO" ? "/pro/dashboard" : "/";
      return NextResponse.redirect(new URL(destination, req.url));
    } catch {
      // אם הטוקן פג תוקף, ימשיך הלאה וימחק ב-catch למטה
    }
  }

  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    const role = payload.role as string;

    if (pathname.startsWith("/admin") && role !== "ADMIN") {
      return NextResponse.redirect(
        new URL(role === "PRO" ? "/pro/dashboard" : "/", req.url)
      );
    }

    if (pathname.startsWith("/pro") && role !== "PRO") {
      return NextResponse.redirect(
        new URL(role === "ADMIN" ? "/admin" : "/", req.url)
      );
    }

    return NextResponse.next();
  } catch {
    // אם השרת נתקל בטוקן לא תקף, הוא ימחק אותו ויעביר ל-login רק אם אנחנו לא ב-login כבר
    if (isPublicPath) {
      const res = NextResponse.next();
      res.cookies.delete("auth_token");
      return res;
    }

    const res = NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete("auth_token");
    return res;
  }
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\..*).*)"],
};