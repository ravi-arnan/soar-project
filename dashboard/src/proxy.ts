import { NextResponse, type NextRequest } from 'next/server';

const INSTALLER_HOSTS = new Set(['soar-agent.raviarnan.dev']);

const ALLOWED_INSTALLER_API_PATHS = [
  '/api/enroll/script',
  '/api/enroll/request',
  '/api/enroll/status',
  '/api/installer/download/',
  '/api/heartbeat',
];

function extractHostname(request: NextRequest): string {
  const raw =
    request.headers.get('x-forwarded-host') ||
    request.headers.get('host') ||
    request.nextUrl.hostname ||
    '';
  return raw.split(',')[0].trim().split(':')[0].toLowerCase();
}

export function proxy(request: NextRequest) {
  const hostname = extractHostname(request);
  if (!INSTALLER_HOSTS.has(hostname)) {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;

  if (
    pathname.startsWith('/_next/') ||
    pathname === '/favicon.ico' ||
    pathname === '/robots.txt'
  ) {
    return NextResponse.next();
  }

  if (pathname.startsWith('/api/')) {
    const allowed = ALLOWED_INSTALLER_API_PATHS.some((entry) =>
      entry.endsWith('/') ? pathname.startsWith(entry) : pathname === entry
    );
    if (allowed) {
      return NextResponse.next();
    }
    return NextResponse.json(
      { error: 'Endpoint tidak tersedia pada host installer' },
      { status: 404 }
    );
  }

  if (pathname === '/install') {
    return NextResponse.next();
  }

  if (pathname === '/') {
    const url = request.nextUrl.clone();
    url.pathname = '/install';
    return NextResponse.rewrite(url);
  }

  const redirectUrl = request.nextUrl.clone();
  redirectUrl.pathname = '/';
  redirectUrl.search = '';
  return NextResponse.redirect(redirectUrl);
}
