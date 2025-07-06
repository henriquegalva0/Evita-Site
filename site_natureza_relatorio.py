import openai
import json
import ast
import os

# Carregar API KEY
apikey = os.environ.get('OPENAI_API_KEY')
if not apikey:
    with open("data/keys/apikeychatgpt.json", "r", encoding="utf8") as arcapikey:
        apikey = json.load(arcapikey)[0]

# Carregar prompt unificado
with open("data/prompts/prompt_gpt_site.json", "r", encoding="utf8") as arcprompt:
    prompt_site = json.load(arcprompt)[0]

# Carregar whitelist de sites parceiros
with open("data/prompts/whitelist_sites_parceiros.json", "r", encoding="utf8") as whitelist_sites_parceiros:
    whitelist_sites = json.load(whitelist_sites_parceiros)[:]

def apichatgptsite(valores):
    """Função unificada para classificação e relatório completo de um site.

    Parâmetros
    ----------
    valores : list
        Lista contendo apenas a URL a ser analisada. Ex.: ["https://exemplo.com"].

    Retorno
    -------
    list
        [classificacao, reputacao, justificativa, seguranca, resposta_raw_dict, cor_hex]
    """
    clas = 'Site Pendente'
    reput = 'Aqui forneceremos dados a respeito da notabilidade do site'
    just = 'Aqui reportaremos informações sobre o julgamento do site'
    segu = 'Aqui recomendaremos medidas de segurança gerais'
    corl = "#58697a"
    resposta_dict = {}

    try:
        client = openai.OpenAI(api_key=f"{apikey}")

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": f"{prompt_site} | {whitelist_sites}"},
                {"role": "user", "content": f"Analise este site: {valores[0]}"}
            ],
            temperature=0,
            max_tokens=2048,
            top_p=1,
            store=False
        )

        print(f"Whitelist de sites parceiros: {whitelist_sites}")
        print(f"Tokens usados (site completo): {response.usage.total_tokens}")

        # Processar resposta
        conteudo_resposta = str(response.choices[0].message.content).lower()
        print(f"Resposta recebida bruta: {conteudo_resposta}")

        try:
            resposta_dict = ast.literal_eval(conteudo_resposta)
        except (ValueError, SyntaxError) as e:
            print(f"Erro ao converter resposta em dict: {e}")
            # Tenta identificar dicionário dentro do texto se houver texto extra
            inicio = conteudo_resposta.find('{')
            fim = conteudo_resposta.rfind('}') + 1
            if inicio != -1 and fim != -1:
                try:
                    resposta_dict = ast.literal_eval(conteudo_resposta[inicio:fim])
                except Exception as ee:
                    print(f"Falha na segunda tentativa de conversão: {ee}")
                    resposta_dict = {}

        # Se obtivemos um dict válido com as chaves esperadas
        if isinstance(resposta_dict, dict) and 'classificacao' in resposta_dict:
            clas = resposta_dict.get('classificacao', clas)
            reput = resposta_dict.get('reputacao', reput)
            just = resposta_dict.get('justificativa', just)
            segu = resposta_dict.get('seguranca', segu)
        else:
            # Resposta inesperada
            print("Estrutura inesperada na resposta da IA.")

        # Determinar cor com base na classificação
        if "confiável" in clas or "confiavel" in clas or "trustworthy" in clas:
            corl = "#27772e"  # Verde
        elif "malicioso" in clas or "malicious" in clas:
            corl = "#961616"  # Vermelho
        elif "não recomendado" in clas or "nao recomendado" in clas or "not recommended" in clas:
            corl = "#733179"  # Roxo suave
        elif "suspeito" in clas or "suspect" in clas:
            corl = "#ffc400"  # Amarelo suave
        else:
            corl = "#58697a"  # Cinza padrão

    except Exception as e:
        print(f"Erro na API: {e}")
        clas = 'Erro na Análise'
        corl = "#58697a"

    return [clas, reput.replace('\n','<br>'), just.replace('\n','<br>'), segu.replace('\n','<br>'), resposta_dict, corl] 