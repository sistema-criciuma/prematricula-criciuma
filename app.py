import os
import re
import csv
import io
import base64
import hashlib
import hmac
import requests
import streamlit as st

TAB_FORMS = "Respostas ao formulário 1"
CACHE_TTL = 120

TAB_BASE_1 = "Educação Infantil Parcial 2026"
TAB_BASE_2 = "Educação Infantil Integral 2026"
TAB_BASE_3 = "Ensino Fundamental Parcial 2026"
TAB_BASE_4 = "Ensino Fundamental Integral 2026"
TAB_BASE_5 = "ABADEUS Integral 2026"

UNIFORME_FIELDS = {
    "Camiseta (uniforme escolar)",
    "Calça (uniforme escolar)",
    "O RECEBIMENTO DA MOCHILA É OPCIONAL. VOCÊ TEM INTERESSE?",
    "O RECEBIMENTO DO TÊNIS SERÁ OPCIONAL. VOCÊ TEM INTERESSE?",
    "Em caso positivo, informe o número do tênis que deseja receber",
    "Jaqueta(uniforme escolar)",
    "ESCOLHA O TAMANHO DA BERMUDA OU SHORT SAIA",
    "ESCOLHA ENTRE BERMUDA OU SHORT SAIA. (SE A MATRÍCULA FOR DE 6º AO 9º DEVERÁ OPTAR POR BERMUDA)",
}


def load_secrets() -> dict:
    # 1) Streamlit Cloud: st.secrets
    try:
        s = dict(st.secrets)
        if s:
            return s
    except Exception:
        pass

    # 2) Local: .streamlit/secrets.toml
    import tomllib
    with open(os.path.join(".streamlit", "secrets.toml"), "rb") as f:
        return tomllib.load(f)


def api_get(url: str, params: dict) -> dict:
    r = requests.get(url, params=params, timeout=60)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok", False):
        raise RuntimeError(f"API ok=false: {data}")
    return data


def normalize_cpf(value) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    s = re.sub(r"\D+", "", s)
    return s.zfill(11) if s else ""


def normalize_escola(s: str) -> str:
    s = "" if s is None else str(s)
    s = " ".join(s.strip().split())
    return s.upper()


def caesar_plus3(s: str) -> str:
    # aplica César +3 só em A-Z / a-z (sem inferir nada além disso)
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(((o - 65 + 3) % 26) + 65))
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 + 3) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def caesar_minus3(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(((o - 65 - 3) % 26) + 65))
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 - 3) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def _b64d(s: str) -> bytes:
    s = (s or "").strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify_pbkdf2_sha256(encoded: str, password: str) -> bool:
    # formato: pbkdf2_sha256$ITER$SALT_B64$HASH_B64
    try:
        parts = (encoded or "").split("$")
        if len(parts) != 4:
            return False
        algo, it_s, salt_b64, hash_b64 = parts
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(it_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


@st.cache_resource
def load_users() -> dict:
    # lê exclusivamente do secrets.toml (USERS_CSV)
    s = load_secrets()
    content = str(s.get("USERS_CSV", "")).strip()
    if not content:
        raise RuntimeError("USERS_CSV não encontrado no secrets.toml.")

    f = io.StringIO(content)
    reader = csv.DictReader(f, delimiter=",")
    if reader.fieldnames:
        reader.fieldnames = [(x or "").strip() for x in reader.fieldnames]

    users = {}
    for row in reader:
        clean = {}
        for k, v in (row or {}).items():
            if k is None:
                continue
            kk = str(k).strip()
            vv = v.strip() if isinstance(v, str) else ("" if v is None else str(v).strip())
            clean[kk] = vv

        usuario = (clean.get("Usuario") or "").strip().upper()
        escola = (clean.get("Escola") or "").strip()
        senha_hash = (clean.get("SenhaHash") or "").strip()

        if not usuario or not senha_hash:
            continue

        users[usuario] = {"escola": escola, "senha_hash": senha_hash}

    if not users:
        raise RuntimeError("USERS_CSV carregou vazio (sem Usuario/SenhaHash).")

    return users


def category_from_source(source_key: str) -> str:
    # categoria unificada (Forms e Base)
    if source_key.endswith("_1"):
        return "Educação Infantil Parcial"
    if source_key.endswith("_2"):
        return "Educação Infantil Integral"
    if source_key.endswith("_3"):
        return "Ensino Fundamental Parcial"
    if source_key.endswith("_4"):
        return "Ensino Fundamental Integral"
    return "ABADEUS"


def pick_first(row: dict, *keys) -> str:
    for k in keys:
        if k in row:
            v = row.get(k)
            if v is None:
                continue
            s = str(v).strip()
            if s != "":
                return s
    return ""


def strip_uniform_fields(full_row: dict) -> dict:
    return {k: v for k, v in full_row.items() if k not in UNIFORME_FIELDS}


def render_record_as_table(d: dict):
    d = strip_uniform_fields(d)
    rows = [{"Campo": k, "Valor": "" if d[k] is None else str(d[k])} for k in d.keys()]
    st.table(rows)


def extract_table_fields(row: dict, source_key: str) -> dict:
    nome = pick_first(row, "Nome do aluno(a)", "Nome")

    cpf_raw = row.get("CPF do(a) aluno(a)")
    cpf = normalize_cpf(cpf_raw)

    turno = pick_first(row, "Turno")
    serie = pick_first(row, "Série", "Série__2")
    situacao = pick_first(row, "Situação")
    protocolo = pick_first(row, "Protocolo")
    carimbo = pick_first(row, "Carimbo de data/hora")
    escola = pick_first(row, "Escola")

    # IMPORTANTE: posição só vem se existir no payload como "Posição"
    # quando não vier (normalmente nos Forms), fica vazio. Sem inferir.
    posicao = pick_first(row, "Posição")

    categoria = category_from_source(source_key)

    if not situacao and source_key.startswith("FORMS_"):
        situacao = "Em espera"

    return {
        "posicao": posicao,
        "categoria": categoria,
        "escola": escola,
        "serie": serie,
        "turno": turno,
        "nome": nome,
        "cpf": cpf,
        "cpf_raw": "" if cpf_raw is None else str(cpf_raw),
        "situacao": situacao,
        "protocolo": protocolo,
        "carimbo": carimbo,
        "_source": source_key,
    }


def fetch_rows(url: str, token: str, tab: str | None, escola_filter: str | None, fields: str) -> list[dict]:
    params = {"token": token, "mode": "rows", "fields": fields, "limit": "2000", "offset": "0"}
    if tab:
        params["tab"] = tab
    if escola_filter:
        params["filter_escola"] = escola_filter

    data = api_get(url, params)
    rows = data.get("rows", []) or []

    total = int(data.get("totalRows") or 0)
    offset = len(rows)
    while offset < total:
        params["offset"] = str(offset)
        chunk = api_get(url, params)
        rows.extend(chunk.get("rows", []) or [])
        offset = len(rows)

    # garantia: se pediu filtro_escola, não pode vir linha de outra escola
    if escola_filter:
        expected = normalize_escola(escola_filter)
        for rr in rows:
            got = normalize_escola(rr.get("Escola", ""))
            if not got or got != expected:
                raise RuntimeError("Filtro de escola falhou: a API retornou linha(s) fora da escola do login.")

    return rows


def fetch_detail_base_by_protocolo(url: str, token: str, tab: str | None, protocolo: str) -> list[dict]:
    prot = (protocolo or "").strip()
    params = {"token": token, "mode": "rows", "fields": "all", "filter_protocolo": prot, "limit": "2000", "offset": "0"}
    if tab:
        params["tab"] = tab

    data = api_get(url, params)
    rows = data.get("rows", []) or []

    # reforço: match exato do protocolo
    prot_up = prot.strip().upper()
    out = []
    for rr in rows:
        p = str(rr.get("Protocolo", "") or "").strip().upper()
        if p == prot_up:
            out.append(rr)
    return out


def fetch_detail_forms_by_cpf_carimbo(url: str, token: str, tab: str, cpf: str, carimbo: str) -> list[dict]:
    params = {
        "token": token,
        "mode": "rows",
        "fields": "all",
        "tab": tab,
        "filter_cpf": cpf,
        "filter_carimbo": carimbo,
        "limit": "2000",
        "offset": "0",
    }
    data = api_get(url, params)
    return data.get("rows", []) or []


@st.cache_data(ttl=CACHE_TTL, show_spinner=True)
def load_school_data_cached(escola: str, is_sme: bool) -> list[dict]:
    s = load_secrets()
    token = str(s["APPS_SCRIPT_TOKEN"]).strip()

    sources = [
        # FORMS: core (sem posição)
        ("FORMS_1", str(s["URL_FORMS_1"]), TAB_FORMS, "core"),
        ("FORMS_2", str(s["URL_FORMS_2"]), TAB_FORMS, "core"),
        ("FORMS_3", str(s["URL_FORMS_3"]), TAB_FORMS, "core"),
        ("FORMS_4", str(s["URL_FORMS_4"]), TAB_FORMS, "core"),
        ("FORMS_5", str(s["URL_FORMS_5"]), TAB_FORMS, "core"),

        # BASE: all para garantir que "Posição" venha quando existir
        ("BASE_1", str(s["URL_BASE_1"]), TAB_BASE_1, "all"),
        ("BASE_2", str(s["URL_BASE_2"]), TAB_BASE_2, "all"),
        ("BASE_3", str(s["URL_BASE_3"]), TAB_BASE_3, "all"),
        ("BASE_4", str(s["URL_BASE_4"]), TAB_BASE_4, "all"),
        ("BASE_5", str(s["URL_BASE_5"]), TAB_BASE_5, "all"),
    ]

    escola_filter = None if is_sme else escola

    out = []
    for key, url, tab, fields in sources:
        rows = fetch_rows(url, token, tab, escola_filter, fields=fields)
        for r in rows:
            out.append(extract_table_fields(r, key))
    return out


def main():
    st.set_page_config(page_title="Pré-matrícula Criciúma - Portal", layout="wide")
    st.title("Pré-matrícula Criciúma - Portal provisório")

    s = load_secrets()
    token = str(s["APPS_SCRIPT_TOKEN"]).strip()

    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
        st.session_state.auth_escola = None
        st.session_state.auth_sme = False

    users = load_users()

    # tela pública + login
    if st.session_state.auth_user is None:
        st.subheader("Consulta por protocolo (responsáveis)")
        colp1, colp2 = st.columns([3, 1])
        protocolo = colp1.text_input("Protocolo", value="", key="public_protocolo")
        if colp2.button("Consultar", key="btn_consultar_protocolo"):
            prot = (protocolo or "").strip()
            if not prot:
                st.warning("Informe o protocolo.")
            else:
                bases = [
                    ("BASE_1", str(s["URL_BASE_1"]), TAB_BASE_1),
                    ("BASE_2", str(s["URL_BASE_2"]), TAB_BASE_2),
                    ("BASE_3", str(s["URL_BASE_3"]), TAB_BASE_3),
                    ("BASE_4", str(s["URL_BASE_4"]), TAB_BASE_4),
                    ("BASE_5", str(s["URL_BASE_5"]), TAB_BASE_5),
                ]

                found = []
                for _, url, tab in bases:
                    rows = fetch_detail_base_by_protocolo(url, token, tab, prot)
                    for r in rows:
                        found.append(r)

                if not found:
                    st.error("Protocolo não encontrado nas planilhas base.")
                else:
                    st.write(f"Encontrado(s): {len(found)}")
                    for i, rr in enumerate(found, start=1):
                        with st.expander(f"Cadastro {i}", expanded=True):
                            render_record_as_table(rr)

        st.divider()

        st.subheader("Acesso escolas / SME")
        with st.form("login_form", clear_on_submit=False):
            u = st.text_input("Usuário", value="")
            p = st.text_input("Senha", value="", type="password")
            ok = st.form_submit_button("Entrar")

        if ok:
            u_norm = (u or "").strip().upper()
            if u_norm not in users:
                st.error("Usuário inválido.")
                return

            stored_hash = (users[u_norm]["senha_hash"] or "").strip()
            entered = (p or "").strip()

            candidates = [
                entered,
                caesar_plus3(entered),
                caesar_minus3(entered),
            ]
            ok_pass = any(verify_pbkdf2_sha256(stored_hash, cand) for cand in candidates)

            if not ok_pass:
                st.error("Senha inválida.")
                return

            escola = users[u_norm]["escola"]
            is_sme = (normalize_escola(escola) == "SME")
            st.session_state.auth_user = u_norm
            st.session_state.auth_escola = escola
            st.session_state.auth_sme = is_sme
            st.rerun()

        return

    # tela logada (sem consulta por protocolo aqui)
    top1, top2, top3 = st.columns([3, 2, 1])
    top1.write(f"Usuário: {st.session_state.auth_user}")
    top2.write(f"Escola: {st.session_state.auth_escola} | Perfil: {'SME' if st.session_state.auth_sme else 'Escola'}")
    if top3.button("Sair"):
        st.session_state.auth_user = None
        st.session_state.auth_escola = None
        st.session_state.auth_sme = False
        st.cache_data.clear()
        st.rerun()

    with st.sidebar:
        if st.button("Recarregar dados (limpar cache)"):
            st.cache_data.clear()
            st.rerun()

    data = load_school_data_cached(st.session_state.auth_escola, st.session_state.auth_sme)

    cats = sorted({x["categoria"] for x in data if x["categoria"]})
    escolas = sorted({x["escola"] for x in data if x["escola"]})
    series = sorted({x["serie"] for x in data if x["serie"]})
    turnos = sorted({x["turno"] for x in data if x["turno"]})
    situacoes = sorted({x["situacao"] for x in data if x["situacao"]})

    f1, f2, f3, f4, f5 = st.columns(5)
    f_cat = f1.selectbox("Categoria", [""] + cats, index=0)
    f_escola = f2.selectbox("Escola", [""] + escolas, index=0)
    f_serie = f3.selectbox("Série", [""] + series, index=0)
    f_turno = f4.selectbox("Turno", [""] + turnos, index=0)
    f_sit = f5.selectbox("Situação", [""] + situacoes, index=0)

    q = st.text_input("Buscar por nome (contém) ou CPF (somente números)", value="")

    def passes(x: dict) -> bool:
        if f_cat and x["categoria"] != f_cat:
            return False
        if f_escola and x["escola"] != f_escola:
            return False
        if f_serie and x["serie"] != f_serie:
            return False
        if f_turno and x["turno"] != f_turno:
            return False
        if f_sit and x["situacao"] != f_sit:
            return False
        if q.strip():
            qq = q.strip().lower()
            if qq.isdigit():
                if qq not in (x.get("cpf") or ""):
                    return False
            else:
                if qq not in (x.get("nome") or "").lower():
                    return False
        return True

    filtered = [x for x in data if passes(x)]
    st.write(f"Registros: {len(filtered)}")

    table = []
    for x in filtered:
        table.append({
            "Posição": x.get("posicao", ""),  # vem da planilha quando existir; quando não vier, fica vazio
            "Situação": x.get("situacao", ""),
            "Categoria": x.get("categoria", ""),
            "Escola": x.get("escola", ""),
            "Série": x.get("serie", ""),
            "Turno": x.get("turno", ""),
            "Nome": x.get("nome", ""),
            "CPF": x.get("cpf_raw") if x.get("cpf_raw") else x.get("cpf", ""),
            "Protocolo": x.get("protocolo", ""),
        })

    st.dataframe(table, use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("Detalhar cadastro (por nome ou CPF)")
    dq = st.text_input("Digite nome (contém) ou CPF (somente números)", value="", key="detail_query")

    def match_detail(x: dict) -> bool:
        if not dq.strip():
            return False
        t = dq.strip().lower()
        if t.isdigit():
            return t in (x.get("cpf") or "")
        return t in (x.get("nome") or "").lower()

    matches = [x for x in filtered if match_detail(x)]

    if dq.strip() and not matches:
        st.info("Nenhum cadastro encontrado para esse nome/CPF dentro dos filtros atuais.")

    if matches:
        if "details_cache" not in st.session_state:
            st.session_state.details_cache = {}

        st.write(f"Encontrados: {len(matches)}")

        for idx, item in enumerate(matches, start=1):
            proto = (item.get("protocolo") or "").strip()
            cpf = (item.get("cpf") or "").strip()
            carimbo = (item.get("carimbo") or "").strip()
            pos = str(item.get("posicao") or "").strip()
            src = item.get("_source")

            stable_id = f"{src}|{proto}|{cpf}|{carimbo}|{pos}"

            resumo = f"{idx} | {item.get('nome','')} | {item.get('serie','')} | {item.get('turno','')} | {item.get('situacao','')}"
            if proto:
                resumo += f" | Protocolo: {proto}"
            if pos:
                resumo += f" | Posição: {pos}"

            with st.expander(resumo, expanded=False):
                if stable_id not in st.session_state.details_cache:
                    if st.button("Carregar detalhes", key=f"btn_detail_{stable_id}"):
                        if src.startswith("BASE_"):
                            if not proto:
                                st.error("Este cadastro não tem protocolo.")
                            else:
                                url = str(s[f"URL_{src}"])
                                tab = {
                                    "BASE_1": TAB_BASE_1,
                                    "BASE_2": TAB_BASE_2,
                                    "BASE_3": TAB_BASE_3,
                                    "BASE_4": TAB_BASE_4,
                                    "BASE_5": TAB_BASE_5,
                                }.get(src)
                                rows = fetch_detail_base_by_protocolo(url, token, tab, proto)
                                if not rows:
                                    st.error("Detalhe não encontrado por protocolo.")
                                else:
                                    st.session_state.details_cache[stable_id] = rows[0]
                                    st.rerun()
                        else:
                            if not cpf or not carimbo:
                                st.error("Este cadastro Forms não tem CPF/carimbo suficientes para detalhar.")
                            else:
                                url = str(s[f"URL_{src}"])
                                rows = fetch_detail_forms_by_cpf_carimbo(url, token, TAB_FORMS, cpf, carimbo)
                                if not rows:
                                    st.error("Detalhe não encontrado por CPF + carimbo.")
                                else:
                                    st.session_state.details_cache[stable_id] = rows[0]
                                    st.rerun()
                else:
                    render_record_as_table(st.session_state.details_cache[stable_id])


if __name__ == "__main__":
    main()
