import os

# AQUI É ONDE VOCÊ VAI ALTERNAR!
# Para rodar localmente, use:
# ENV = 'development'

# Para rodar no Render, use:
# ENV = 'production'
# USE_RENDER = True

# Para rodar em produção (evita-ai.com), use:
ENV = 'production'

# O resto do arquivo permanece igual
BASE_URLS = {
    'development': 'http://localhost:5000',
    'render': 'https://evita-ai.onrender.com',
    'production': 'https://evita-ai.com'
}

def get_base_url():
    if ENV == 'development':
        return BASE_URLS['development']
    elif os.environ.get('USE_RENDER_URI') == 'true' or globals().get('USE_RENDER', False):
        return BASE_URLS['render']
    else:
        return BASE_URLS['production']

OAUTH_CALLBACK_URL = f"{get_base_url()}/oauth/callback"
DEBUG = ENV == 'development'

# Nova configuração para OAuth
OAUTHLIB_INSECURE_TRANSPORT = ENV == 'development'
