"""
ShopTrack Ecommerce Analytics
Sample file for Camiro compliance demo.

This code is intentionally non-compliant for demonstration purposes.
Tracking fires before consent is obtained.
"""

from flask import Flask, request, render_template_string
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Tracking scripts loaded immediately - before consent
TRACKING_SCRIPTS = """
<!-- Google Analytics - fires before consent -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GTM-XXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA-XXXXXXX');
</script>

<!-- Meta Pixel - fires before consent -->
<script>
!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){...};
n.push=n;n.loaded=!0;n.version='2.0';
fbq('init', '123456789');
fbq('track', 'PageView');
</script>

<!-- Mixpanel - fires before consent -->
<script>
(function(c,a){window.mixpanel=a;...})(document,window.mixpanel||[]);
mixpanel.init('YOUR_TOKEN');
mixpanel.track('Page View');
</script>
"""


@app.route('/')
def homepage():
    user_id = request.cookies.get('user_id')
    session_id = request.cookies.get('session_id')

    # Track user immediately - no consent check
    track_pageview(user_id, session_id, '/')

    return render_template_string(f"""
    <html>
    <head>{TRACKING_SCRIPTS}</head>
    <body>
        <h1>Welcome to ShopTrack</h1>
    </body>
    </html>
    """)


@app.route('/product/<int:product_id>')
def product_page(product_id):
    user_id = request.cookies.get('user_id')

    # Log user identity with browsing behaviour
    logger.info(f"User {user_id} email={get_user_email(user_id)} viewed product {product_id}")

    # Track before consent
    track_product_view(user_id, product_id)

    return f"Product {product_id}"


def track_pageview(user_id, session_id, page):
    """Track pageview - called before consent obtained."""
    import requests
    # Send to analytics - no consent check
    requests.post('https://api.segment.com/v1/track', json={
        'userId': user_id,
        'event': 'Page Viewed',
        'properties': {'page': page, 'session': session_id}
    })

    # Also store in localStorage equivalent
    analytics_data = {
        'user_id': user_id,
        'session_id': session_id,
        'page': page,
        'timestamp': str(__import__('datetime').datetime.now())
    }
    store_analytics(analytics_data)


def track_product_view(user_id, product_id):
    """Track product view with user identity."""
    import requests
    requests.post('https://api.amplitude.com/2/httpapi', json={
        'api_key': 'AMPLITUDE_KEY',
        'events': [{
            'user_id': user_id,
            'event_type': 'Product Viewed',
            'event_properties': {'product_id': product_id}
        }]
    })


def store_analytics(data: dict):
    """Store analytics data - no retention limit defined."""
    import sqlite3
    db = sqlite3.connect('analytics.db')
    db.execute(
        "INSERT INTO events (user_id, session_id, page, timestamp) VALUES (?,?,?,?)",
        [data['user_id'], data['session_id'], data['page'], data['timestamp']]
    )
    db.commit()


def get_user_email(user_id):
    """Get user email for logging."""
    import sqlite3
    db = sqlite3.connect('shoptrack.db')
    row = db.execute("SELECT email FROM users WHERE id=?", [user_id]).fetchone()
    return row[0] if row else None


@app.route('/checkout')
def checkout():
    user_id = request.cookies.get('user_id')
    email = get_user_email(user_id)

    # Log sensitive checkout data
    logger.info(f"Checkout initiated: user={user_id} email={email} ip={request.remote_addr}")

    # Set cookie without security attributes
    response = app.make_response("Checkout")
    response.set_cookie('cart_id', 'some_value')  # No HttpOnly, no Secure, no SameSite

    return response
