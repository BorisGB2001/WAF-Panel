--
-- PostgreSQL database dump
--

-- Dumped from database version 15.2 (Debian 15.2-1.pgdg110+1)
-- Dumped by pg_dump version 15.2 (Debian 15.2-1.pgdg110+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: mgt_acl_blocked_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_acl_blocked_ip (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    ip text,
    site_id bigint,
    country text,
    province text,
    city text,
    denied_count bigint,
    status bigint,
    valid_before timestamp with time zone,
    reason text,
    result text,
    block_min bigint,
    action text,
    period bigint,
    count bigint,
    query_key text
);


--
-- Name: mgt_acl_blocked_ip_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_acl_blocked_ip_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_acl_blocked_ip_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_acl_blocked_ip_id_seq OWNED BY public.mgt_acl_blocked_ip.id;


--
-- Name: mgt_acl_config_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_acl_config_v2 (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    type text,
    path_prefix text,
    period bigint,
    count bigint,
    block_min bigint,
    enabled boolean,
    action text,
    exclude_content_type text[],
    status_code integer[],
    use_global boolean DEFAULT false
);


--
-- Name: mgt_acl_config_v2_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_acl_config_v2_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_acl_config_v2_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_acl_config_v2_id_seq OWNED BY public.mgt_acl_config_v2.id;


--
-- Name: mgt_acl_config_v3; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_acl_config_v3 (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    type text,
    name text,
    priority bigint,
    enabled boolean,
    conditions jsonb,
    period bigint,
    count bigint,
    action text,
    block_min bigint,
    use_global boolean,
    built_in boolean,
    custom_status_codes text[]
);


--
-- Name: mgt_acl_config_v3_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_acl_config_v3_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_acl_config_v3_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_acl_config_v3_id_seq OWNED BY public.mgt_acl_config_v3.id;


--
-- Name: mgt_acl_ip_req_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_acl_ip_req_log (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    ip text,
    country text,
    province text,
    city text,
    count bigint,
    action bigint
);


--
-- Name: mgt_acl_ip_req_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_acl_ip_req_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_acl_ip_req_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_acl_ip_req_log_id_seq OWNED BY public.mgt_acl_ip_req_log.id;


--
-- Name: mgt_alarm; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_alarm (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event json,
    platform json,
    site_ids integer[],
    network_proxy boolean,
    cur_platform text
);


--
-- Name: mgt_alarm_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_alarm_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_alarm_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_alarm_id_seq OWNED BY public.mgt_alarm.id;


--
-- Name: mgt_anti_tamper; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_anti_tamper (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    content_type text,
    path text,
    req_header text,
    changed boolean,
    cache_header bytea,
    cache_content bytea,
    cache_sha256 text,
    cache_time timestamp with time zone,
    change_header bytea,
    change_content bytea,
    change_sha256 text,
    change_time timestamp with time zone
);


--
-- Name: mgt_anti_tamper_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_anti_tamper_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_anti_tamper_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_anti_tamper_id_seq OWNED BY public.mgt_anti_tamper.id;


--
-- Name: mgt_api; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_api (
    id bigint NOT NULL,
    path text,
    "time" bigint,
    frontend boolean,
    count bigint
);


--
-- Name: mgt_api_asset; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_api_asset (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    uuid text,
    site_uuid bigint,
    protocol text,
    host text,
    port bigint,
    urlpath text,
    method text,
    content_type text,
    active_time bigint
);


--
-- Name: mgt_api_asset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_api_asset_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_api_asset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_api_asset_id_seq OWNED BY public.mgt_api_asset.id;


--
-- Name: mgt_api_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_api_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_api_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_api_id_seq OWNED BY public.mgt_api.id;


--
-- Name: mgt_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_audit_log (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    user_id bigint,
    username text,
    content text,
    ip bytea
);


--
-- Name: mgt_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_audit_log_id_seq OWNED BY public.mgt_audit_log.id;


--
-- Name: mgt_auth_defense; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    comment text,
    pattern jsonb,
    is_enabled boolean,
    username text,
    password text
);


--
-- Name: COLUMN mgt_auth_defense.comment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.mgt_auth_defense.comment IS 'COMMENT';


--
-- Name: mgt_auth_defense_blocked_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_blocked_ip (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event_id text,
    site_id bigint,
    ip text,
    rule_id bigint,
    country text,
    province text,
    city text,
    username text,
    trigger_count bigint,
    pass_count bigint,
    deny_count bigint,
    started_at bigint,
    ended_at bigint,
    dur_sec bigint
);


--
-- Name: mgt_auth_defense_blocked_ip_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_blocked_ip_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_blocked_ip_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_blocked_ip_id_seq OWNED BY public.mgt_auth_defense_blocked_ip.id;


--
-- Name: mgt_auth_defense_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_id_seq OWNED BY public.mgt_auth_defense.id;


--
-- Name: mgt_auth_defense_source; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_source (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    comment text,
    type bigint,
    "user" jsonb,
    auth jsonb,
    network_proxy boolean DEFAULT false,
    association smallint DEFAULT 0,
    title text
);


--
-- Name: mgt_auth_defense_source_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_source_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_source_id_seq OWNED BY public.mgt_auth_defense_source.id;


--
-- Name: mgt_auth_defense_source_user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_source_user (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    auth_source_id bigint,
    uid text,
    uname text,
    status bigint,
    last_login bigint
);


--
-- Name: mgt_auth_defense_source_user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_source_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_source_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_source_user_id_seq OWNED BY public.mgt_auth_defense_source_user.id;


--
-- Name: mgt_auth_defense_user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_user (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    username text,
    password text,
    last_login bigint,
    wap_uid text,
    github_id text,
    cas_uid text,
    old_version boolean,
    email text,
    phone text,
    tfa_enabled boolean,
    tfa_secret text DEFAULT ''::text
);


--
-- Name: mgt_auth_defense_user_bind; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_user_bind (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    user_id bigint,
    source_type bigint,
    third_id text
);


--
-- Name: mgt_auth_defense_user_bind_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_user_bind_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_user_bind_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_user_bind_id_seq OWNED BY public.mgt_auth_defense_user_bind.id;


--
-- Name: mgt_auth_defense_user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_user_id_seq OWNED BY public.mgt_auth_defense_user.id;


--
-- Name: mgt_auth_defense_user_review; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_user_review (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    uuid text DEFAULT gen_random_uuid(),
    node text,
    site_id bigint,
    auth_user_id bigint,
    username text,
    status bigint,
    request_time bigint,
    new boolean,
    github_id text,
    wap_uid text,
    cas_uid text,
    auth_source_id bigint,
    third_id text
);


--
-- Name: mgt_auth_defense_user_review_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_user_review_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_user_review_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_user_review_id_seq OWNED BY public.mgt_auth_defense_user_review.id;


--
-- Name: mgt_auth_defense_user_site; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_user_site (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    auth_user_id bigint,
    status bigint
);


--
-- Name: mgt_auth_defense_user_site_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_user_site_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_user_site_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_user_site_id_seq OWNED BY public.mgt_auth_defense_user_site.id;


--
-- Name: mgt_auth_defense_verify; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_defense_verify (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    username text,
    result boolean,
    status bigint,
    ip text,
    country text,
    province text,
    city text,
    auth_source_id bigint,
    site_id bigint,
    policy_id bigint,
    user_id bigint,
    source_type bigint,
    uuid text,
    third_id text
);


--
-- Name: mgt_auth_defense_verify_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_defense_verify_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_defense_verify_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_defense_verify_id_seq OWNED BY public.mgt_auth_defense_verify.id;


--
-- Name: mgt_auth_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_auth_token (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    type bigint DEFAULT 0,
    token text,
    expire bigint
);


--
-- Name: mgt_auth_token_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_auth_token_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_auth_token_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_auth_token_id_seq OWNED BY public.mgt_auth_token.id;


--
-- Name: mgt_behaviour; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_behaviour (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    src_router text,
    dst_router text
);


--
-- Name: mgt_behaviour_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_behaviour_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_behaviour_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_behaviour_id_seq OWNED BY public.mgt_behaviour.id;


--
-- Name: mgt_challenge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_challenge (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    comment text,
    pattern jsonb,
    is_enabled boolean
);


--
-- Name: COLUMN mgt_challenge.comment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.mgt_challenge.comment IS 'COMMENT';


--
-- Name: mgt_challenge_blocked_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_challenge_blocked_ip (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event_id text,
    ip text,
    site_id bigint,
    rule_id bigint,
    country text,
    province text,
    city text,
    trigger_count bigint,
    pass_count bigint,
    started_at bigint,
    ended_at bigint,
    dur_sec bigint
);


--
-- Name: mgt_challenge_blocked_ip_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_challenge_blocked_ip_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_challenge_blocked_ip_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_challenge_blocked_ip_id_seq OWNED BY public.mgt_challenge_blocked_ip.id;


--
-- Name: mgt_challenge_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_challenge_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_challenge_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_challenge_id_seq OWNED BY public.mgt_challenge.id;


--
-- Name: mgt_challenge_session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_challenge_session (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    session character varying(64),
    deadline bigint
);


--
-- Name: mgt_challenge_session_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_challenge_session_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_challenge_session_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_challenge_session_id_seq OWNED BY public.mgt_challenge_session.id;


--
-- Name: mgt_chaos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_chaos (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    is_enabled boolean,
    website_id bigint,
    html_encryption boolean,
    html_fast_decryption boolean,
    js_encryption boolean,
    js_path text[],
    img_encryption boolean,
    img_watermark text,
    img_text text
);


--
-- Name: mgt_chaos_cnt; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_chaos_cnt (
    id bigint NOT NULL,
    date text,
    req_cnt bigint
);


--
-- Name: mgt_chaos_cnt_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_chaos_cnt_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_chaos_cnt_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_chaos_cnt_id_seq OWNED BY public.mgt_chaos_cnt.id;


--
-- Name: mgt_chaos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_chaos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_chaos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_chaos_id_seq OWNED BY public.mgt_chaos.id;


--
-- Name: mgt_cloud_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_cloud_policy (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    action bigint,
    name text
);


--
-- Name: mgt_cloud_policy_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_cloud_policy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_cloud_policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_cloud_policy_id_seq OWNED BY public.mgt_cloud_policy.id;


--
-- Name: mgt_detect_log_basic; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_detect_log_basic (
    id bigint NOT NULL,
    created_at bigint,
    updated_at timestamp with time zone,
    event_id text NOT NULL,
    site_uuid text,
    src_ip text,
    socket_ip text,
    protocol bigint,
    host text,
    url_path text,
    dst_port bigint,
    country text,
    province text,
    city text,
    lng text DEFAULT ''::text,
    lat text DEFAULT ''::text,
    attack_type bigint,
    risk_level bigint,
    action bigint,
    rule_id text,
    policy_name text,
    ja4_fingerprint text,
    "timestamp" bigint,
    rule_id_list text[]
);


--
-- Name: mgt_detect_log_basic_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_detect_log_basic_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_detect_log_basic_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_detect_log_basic_id_seq OWNED BY public.mgt_detect_log_basic.id;


--
-- Name: mgt_detect_log_detail; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_detect_log_detail (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event_id text NOT NULL,
    src_port bigint,
    dst_ip text,
    method text,
    query_string text,
    status_code bigint,
    req_header text,
    req_body text,
    rsp_header text,
    rsp_body text,
    payload text,
    location text,
    decode_path text,
    "timestamp" bigint
);


--
-- Name: mgt_detect_log_detail_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_detect_log_detail_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_detect_log_detail_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_detect_log_detail_id_seq OWNED BY public.mgt_detect_log_detail.id;


--
-- Name: mgt_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_event (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_uuid text,
    ip text,
    protocol bigint,
    host text,
    dst_port bigint,
    deny_count bigint,
    pass_count bigint,
    end_at timestamp with time zone,
    finished boolean,
    country text,
    province text,
    city text,
    lat text,
    lng text
);


--
-- Name: mgt_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_event_id_seq OWNED BY public.mgt_event.id;


--
-- Name: mgt_forwarding_rule; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_forwarding_rule (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint NOT NULL,
    path_prefix text NOT NULL,
    upstreams jsonb,
    comment text,
    is_enabled boolean NOT NULL
);


--
-- Name: mgt_forwarding_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_forwarding_rule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_forwarding_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_forwarding_rule_id_seq OWNED BY public.mgt_forwarding_rule.id;


--
-- Name: mgt_fsl_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_fsl_history (
    id bigint NOT NULL,
    last_pushed_at timestamp with time zone,
    hash text,
    content text,
    count bigint
);


--
-- Name: mgt_fsl_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_fsl_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_fsl_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_fsl_history_id_seq OWNED BY public.mgt_fsl_history.id;


--
-- Name: mgt_interest_point; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_interest_point (
    id bigint NOT NULL,
    source character varying(32) NOT NULL,
    type bigint NOT NULL,
    count bigint
);


--
-- Name: mgt_interest_point_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_interest_point_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_interest_point_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_interest_point_id_seq OWNED BY public.mgt_interest_point.id;


--
-- Name: mgt_ip_group; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_ip_group (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    comment text,
    ips jsonb,
    ip_text text,
    reference text,
    builtin boolean
);


--
-- Name: COLUMN mgt_ip_group.comment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.mgt_ip_group.comment IS 'COMMENT';


--
-- Name: mgt_ip_group_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_ip_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_ip_group_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_ip_group_id_seq OWNED BY public.mgt_ip_group.id;


--
-- Name: mgt_ja4_library; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_ja4_library (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    ja4 text,
    count bigint,
    builtin boolean,
    pro boolean
);


--
-- Name: mgt_ja4_library_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_ja4_library_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_ja4_library_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_ja4_library_id_seq OWNED BY public.mgt_ja4_library.id;


--
-- Name: mgt_lock; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_lock (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    key text
);


--
-- Name: mgt_lock_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_lock_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_lock_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_lock_id_seq OWNED BY public.mgt_lock.id;


--
-- Name: mgt_master_sync_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_master_sync_event (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    uuid text,
    node text,
    table_name text,
    data jsonb
);


--
-- Name: mgt_master_sync_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_master_sync_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_master_sync_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_master_sync_event_id_seq OWNED BY public.mgt_master_sync_event.id;


--
-- Name: mgt_node_key; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_node_key (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    uuid text DEFAULT gen_random_uuid(),
    node text,
    fingerprint text,
    public_key text
);


--
-- Name: mgt_node_key_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_node_key_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_node_key_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_node_key_id_seq OWNED BY public.mgt_node_key.id;


--
-- Name: mgt_options; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_options (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    key text,
    value text
);


--
-- Name: mgt_options_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_options_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_options_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_options_id_seq OWNED BY public.mgt_options.id;


--
-- Name: mgt_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_policy (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    action bigint,
    mix_actions integer[],
    name text,
    pattern jsonb,
    is_enabled boolean,
    username text,
    password text,
    "user" jsonb,
    log boolean,
    builtin boolean,
    hidden boolean,
    priority bigint DEFAULT 0,
    level bigint,
    expire bigint,
    replay boolean,
    cloud_id bigint,
    cloud_total bigint,
    parent_id bigint DEFAULT 0,
    black_rule bigint,
    white_rule bigint,
    auth_rule bigint,
    captcha_rule bigint,
    compatible bigint,
    auth_source_ids bigint[],
    auth_defense_portal boolean DEFAULT false NOT NULL,
    negate boolean DEFAULT false,
    site_id bigint DEFAULT 0,
    "order" bigint DEFAULT 0,
    review bigint DEFAULT 0,
    auth_callback text,
    tfa_enabled boolean DEFAULT false,
    last_modified_by character varying(255),
    monitor boolean DEFAULT false
);


--
-- Name: mgt_policy_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_policy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_policy_id_seq OWNED BY public.mgt_policy.id;


--
-- Name: mgt_policy_rule; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_policy_rule (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    action bigint,
    comment text,
    pattern jsonb,
    is_enabled boolean,
    builtin boolean
);


--
-- Name: COLUMN mgt_policy_rule.comment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.mgt_policy_rule.comment IS 'COMMENT';


--
-- Name: mgt_policy_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_policy_rule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_policy_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_policy_rule_id_seq OWNED BY public.mgt_policy_rule.id;


--
-- Name: mgt_proxy_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_proxy_config (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    ssl_protocols jsonb,
    ssl_ciphers jsonb,
    force_https jsonb,
    hsts jsonb,
    hsts_max_age jsonb,
    hsts_preload jsonb,
    hsts_sub jsonb,
    host jsonb,
    xfp jsonb,
    xfh jsonb,
    gzip jsonb,
    br jsonb,
    http2 jsonb,
    http3 jsonb,
    ipv6 jsonb,
    ip_source text,
    ip_value text,
    http_headers jsonb,
    http_1dot0 jsonb,
    reset_xff jsonb,
    default_server jsonb,
    sse jsonb,
    ntlm jsonb
);


--
-- Name: mgt_proxy_config_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_proxy_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_proxy_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_proxy_config_id_seq OWNED BY public.mgt_proxy_config.id;


--
-- Name: mgt_report; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_report (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    data bytea,
    begin_time bigint,
    end_time bigint,
    state text,
    error text
);


--
-- Name: mgt_report_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_report_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_report_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_report_id_seq OWNED BY public.mgt_report.id;


--
-- Name: mgt_rule_detect_log_basic; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_rule_detect_log_basic (
    id bigint NOT NULL,
    created_at bigint,
    updated_at timestamp with time zone,
    event_id text NOT NULL,
    site_uuid text,
    src_ip text,
    socket_ip text,
    ja4_fingerprint text,
    protocol bigint,
    host text,
    url_path text,
    dst_port bigint,
    country text,
    province text,
    city text,
    lng text DEFAULT ''::text,
    lat text DEFAULT ''::text,
    attack_type bigint,
    risk_level bigint,
    action bigint,
    rule_id text,
    policy_name text,
    "timestamp" bigint,
    rule_id_list text[],
    policy_rule_id bigint DEFAULT 0,
    policy_rule_parent_id bigint DEFAULT 0
);


--
-- Name: mgt_rule_detect_log_basic_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_rule_detect_log_basic_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_rule_detect_log_basic_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_rule_detect_log_basic_id_seq OWNED BY public.mgt_rule_detect_log_basic.id;


--
-- Name: mgt_rule_detect_log_detail; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_rule_detect_log_detail (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event_id text NOT NULL,
    src_port bigint,
    dst_ip text,
    method text,
    query_string text,
    status_code bigint,
    req_header text,
    req_body text,
    rsp_header text,
    rsp_body text,
    payload text,
    location text,
    decode_path text,
    "timestamp" bigint
);


--
-- Name: mgt_rule_detect_log_detail_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_rule_detect_log_detail_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_rule_detect_log_detail_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_rule_detect_log_detail_id_seq OWNED BY public.mgt_rule_detect_log_detail.id;


--
-- Name: mgt_rule_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_rule_event (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    ip text,
    site_uuid text,
    protocol bigint,
    host text,
    dst_port bigint,
    deny_count bigint,
    pass_count bigint,
    end_at timestamp with time zone,
    finished boolean,
    country text,
    province text,
    city text,
    lat text,
    lng text
);


--
-- Name: mgt_rule_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_rule_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_rule_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_rule_event_id_seq OWNED BY public.mgt_rule_event.id;


--
-- Name: mgt_security_posture; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_security_posture (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    "timestamp" bigint DEFAULT 0,
    day_timestamp bigint DEFAULT 0,
    attack_deny bigint DEFAULT 0,
    attack_allow bigint DEFAULT 0,
    black_hit bigint DEFAULT 0,
    black_deny bigint DEFAULT 0,
    black_allow bigint DEFAULT 0,
    white_hit bigint DEFAULT 0,
    acl_hit bigint DEFAULT 0,
    waiting_hit bigint DEFAULT 0,
    challenge_deny bigint DEFAULT 0,
    challenge_allow bigint DEFAULT 0,
    auth_deny bigint DEFAULT 0,
    auth_allow bigint DEFAULT 0,
    anti_tamper jsonb,
    attack_ip jsonb,
    black_white_ip jsonb,
    acl_ip jsonb,
    challenge_deny_ip jsonb,
    attack_type jsonb,
    black_white_rule jsonb,
    attack_domain jsonb,
    attack_page jsonb
);


--
-- Name: mgt_security_posture_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_security_posture_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_security_posture_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_security_posture_id_seq OWNED BY public.mgt_security_posture.id;


--
-- Name: mgt_share_plan_v2_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_share_plan_v2_config (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    server_address text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: mgt_skynet_moudle; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_skynet_moudle (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    semantics jsonb
);


--
-- Name: mgt_skynet_moudle_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_skynet_moudle_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_skynet_moudle_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_skynet_moudle_id_seq OWNED BY public.mgt_skynet_moudle.id;


--
-- Name: mgt_ssl_cert; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_ssl_cert (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    domain jsonb,
    issuer text,
    self_signature boolean,
    trusted boolean,
    revoked boolean,
    expired boolean,
    cert_type bigint,
    email text,
    acme_message text,
    valid_before timestamp with time zone,
    cert_content text,
    key_content text
);


--
-- Name: mgt_ssl_cert_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_ssl_cert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_ssl_cert_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_ssl_cert_id_seq OWNED BY public.mgt_ssl_cert.id;


--
-- Name: mgt_statistics_agg; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_statistics_agg (
    id bigint NOT NULL,
    type text,
    "time" bigint,
    day_time bigint,
    hour_time bigint,
    key text,
    count bigint
);


--
-- Name: mgt_statistics_agg_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_statistics_agg_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_statistics_agg_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_statistics_agg_id_seq OWNED BY public.mgt_statistics_agg.id;


--
-- Name: mgt_sync_client; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_sync_client (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    client_id text,
    client_ip text,
    client_ver text,
    master text,
    token text,
    expired_at bigint,
    client_cert text,
    client_key text,
    ca_cert text,
    master_ca text,
    master_fingerprint text,
    master_server_name text
);


--
-- Name: mgt_sync_client_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_sync_client_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_sync_client_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_sync_client_id_seq OWNED BY public.mgt_sync_client.id;


--
-- Name: mgt_sync_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_sync_log (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    action text,
    reason text,
    client_id text
);


--
-- Name: mgt_sync_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_sync_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_sync_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_sync_log_id_seq OWNED BY public.mgt_sync_log.id;


--
-- Name: mgt_sync_static_task; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_sync_static_task (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    node text,
    site_id bigint,
    task_id text,
    status integer
);


--
-- Name: mgt_sync_static_task_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_sync_static_task_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_sync_static_task_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_sync_static_task_id_seq OWNED BY public.mgt_sync_static_task.id;


--
-- Name: mgt_sync_table; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_sync_table (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    node text,
    name text,
    last_sync bigint,
    client_id text
);


--
-- Name: mgt_sync_table_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_sync_table_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_sync_table_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_sync_table_id_seq OWNED BY public.mgt_sync_table.id;


--
-- Name: mgt_sync_task; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_sync_task (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    node text,
    task_id text,
    task_name text,
    table_name text,
    "from" bigint,
    "to" bigint,
    skip integer,
    "limit" integer,
    status integer,
    data bytea,
    "full" boolean,
    error text,
    start_time bigint,
    end_time bigint,
    cost bigint,
    logs jsonb,
    client_id text,
    full_end boolean
);


--
-- Name: mgt_sync_task_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_sync_task_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_sync_task_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_sync_task_id_seq OWNED BY public.mgt_sync_task.id;


--
-- Name: mgt_system_statistics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_system_statistics (
    id bigint NOT NULL,
    type text,
    value bigint,
    created_at timestamp with time zone,
    website text,
    country text,
    province text,
    city text,
    source_id text
);


--
-- Name: mgt_system_statistics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_system_statistics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_system_statistics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_system_statistics_id_seq OWNED BY public.mgt_system_statistics.id;


--
-- Name: mgt_user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_user (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    role bigint DEFAULT 1,
    username text NOT NULL,
    password text,
    password_enabled boolean,
    kdf text,
    salt text,
    tfa_enabled boolean,
    tfa_binded boolean,
    tfa_secret text,
    jwt_version bigint,
    last_login timestamp with time zone,
    pwd_updated_at timestamp with time zone,
    api_token text,
    third_id text
);


--
-- Name: mgt_user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_user_id_seq OWNED BY public.mgt_user.id;


--
-- Name: mgt_user_lock; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_user_lock (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    username text NOT NULL,
    failed bigint DEFAULT 0,
    lock_until bigint DEFAULT 0,
    last_failed_at bigint DEFAULT 0
);


--
-- Name: mgt_user_lock_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_user_lock_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_user_lock_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_user_lock_id_seq OWNED BY public.mgt_user_lock.id;


--
-- Name: mgt_waiting_room; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_waiting_room (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    is_enabled boolean,
    max_concurrent bigint,
    max_waiting bigint,
    session_timeout bigint,
    website_id bigint
);


--
-- Name: mgt_waiting_room_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_waiting_room_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_waiting_room_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_waiting_room_id_seq OWNED BY public.mgt_waiting_room.id;


--
-- Name: mgt_website; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_website (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    group_id bigint DEFAULT 0 NOT NULL,
    comment text,
    server_names jsonb,
    ports jsonb,
    upstreams jsonb,
    is_enabled boolean,
    health_failed jsonb,
    load_balance jsonb,
    exclude_paths jsonb,
    exclude_content_type jsonb,
    mode bigint DEFAULT 0,
    static boolean DEFAULT false,
    type bigint DEFAULT 0,
    index text DEFAULT 'index.html'::text,
    static_default bigint DEFAULT 1,
    redirect_status_code bigint DEFAULT 0,
    cert_type bigint,
    cert_id bigint DEFAULT 0,
    cert_filename text,
    key_filename text,
    email text,
    title text,
    icon_base64 text,
    user_icon_base64 text,
    acl_response_status_code bigint,
    acl_response_html_path text,
    forbidden_status_code bigint,
    forbidden_html_path text,
    not_found_status_code bigint,
    not_found_html_path text,
    offline_status_code bigint,
    offline_html_path text,
    bad_gateway_status_code bigint,
    bad_gateway_html_path text,
    gateway_timeout_status_code bigint,
    gateway_timeout_html_path text,
    auth_defense_id bigint DEFAULT 0 NOT NULL,
    challenge_id bigint DEFAULT 0 NOT NULL,
    chaos_id bigint DEFAULT 0 NOT NULL,
    chaos_is_enabled boolean DEFAULT false NOT NULL,
    access_log_limit bigint DEFAULT 0 NOT NULL,
    error_log_limit bigint DEFAULT 0 NOT NULL,
    acl_enabled boolean DEFAULT false NOT NULL,
    tamper_refresh bigint,
    tamper_refresh_state text,
    wr_id bigint DEFAULT 0 NOT NULL,
    custom_location text[],
    health_check boolean DEFAULT false NOT NULL,
    portal boolean DEFAULT false NOT NULL,
    portal_redirect text,
    "position" bigint,
    stat_enabled boolean DEFAULT false NOT NULL,
    sp_enabled boolean DEFAULT false NOT NULL,
    description text,
    challenge_is_enabled boolean DEFAULT false NOT NULL,
    health_check_interval bigint DEFAULT 0 NOT NULL,
    auth_challenge_timeout bigint DEFAULT 1 NOT NULL,
    auth_challenge_timeout_unit character varying(16) DEFAULT 'hour'::character varying NOT NULL
);


--
-- Name: mgt_website_group; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_website_group (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name text,
    "position" bigint
);


--
-- Name: mgt_website_group_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_website_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_website_group_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_website_group_id_seq OWNED BY public.mgt_website_group.id;


--
-- Name: mgt_website_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_website_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_website_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_website_id_seq OWNED BY public.mgt_website.id;


--
-- Name: mgt_wr_stat_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mgt_wr_stat_log (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    event_id text,
    site_id bigint,
    rule_id bigint,
    max_concurrent bigint,
    session_timeout bigint,
    total_waiting bigint,
    top_waiting bigint,
    cur_waiting bigint,
    total_waiting_time bigint,
    total_serving bigint,
    avg_wait_sec bigint,
    bounce_rate numeric,
    dur_sec bigint,
    started_at bigint,
    ended_at bigint
);


--
-- Name: mgt_wr_stat_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mgt_wr_stat_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mgt_wr_stat_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mgt_wr_stat_log_id_seq OWNED BY public.mgt_wr_stat_log.id;


--
-- Name: policy_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_records (
    id bigint NOT NULL,
    "time" bigint,
    site_id bigint,
    policy_id bigint,
    req_count bigint DEFAULT 0,
    pass_count bigint DEFAULT 0
);


--
-- Name: policy_records_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policy_records_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policy_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policy_records_id_seq OWNED BY public.policy_records.id;


--
-- Name: qps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.qps (
    id bigint NOT NULL,
    site_id bigint,
    "time" timestamp with time zone,
    points text,
    count bigint
);


--
-- Name: qps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.qps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: qps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.qps_id_seq OWNED BY public.qps.id;


--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resources (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    path text,
    method text,
    status_code bigint,
    content_type text,
    content_length bigint,
    req_header text,
    response_time bigint,
    req_today bigint
);


--
-- Name: resources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.resources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.resources_id_seq OWNED BY public.resources.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);


--
-- Name: sites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sites (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    site_id bigint,
    ignored_prefixes text,
    ignored_contente_types text
);


--
-- Name: sites_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sites_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sites_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sites_id_seq OWNED BY public.sites.id;


--
-- Name: statistics_basics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.statistics_basics (
    id bigint NOT NULL,
    type text,
    "time" bigint,
    hour_time bigint,
    day_time bigint,
    key text,
    content_type text,
    method text,
    path text,
    site_id text,
    count bigint
);


--
-- Name: statistics_basics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.statistics_basics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: statistics_basics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.statistics_basics_id_seq OWNED BY public.statistics_basics.id;


--
-- Name: statistics_geos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.statistics_geos (
    id bigint NOT NULL,
    "time" bigint,
    country text,
    province text,
    city text,
    count bigint,
    attack_type bigint,
    action bigint
);


--
-- Name: statistics_geos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.statistics_geos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: statistics_geos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.statistics_geos_id_seq OWNED BY public.statistics_geos.id;


--
-- Name: statistics_ips; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.statistics_ips (
    id bigint NOT NULL,
    "time" bigint,
    day_time bigint,
    key text,
    count bigint,
    attack_type bigint,
    action bigint
);


--
-- Name: statistics_ips_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.statistics_ips_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: statistics_ips_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.statistics_ips_id_seq OWNED BY public.statistics_ips.id;


--
-- Name: statistics_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.statistics_sessions (
    id bigint NOT NULL,
    "time" bigint,
    day_time bigint,
    key text,
    count bigint
);


--
-- Name: statistics_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.statistics_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: statistics_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.statistics_sessions_id_seq OWNED BY public.statistics_sessions.id;


--
-- Name: mgt_acl_blocked_ip id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_blocked_ip ALTER COLUMN id SET DEFAULT nextval('public.mgt_acl_blocked_ip_id_seq'::regclass);


--
-- Name: mgt_acl_config_v2 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_config_v2 ALTER COLUMN id SET DEFAULT nextval('public.mgt_acl_config_v2_id_seq'::regclass);


--
-- Name: mgt_acl_config_v3 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_config_v3 ALTER COLUMN id SET DEFAULT nextval('public.mgt_acl_config_v3_id_seq'::regclass);


--
-- Name: mgt_acl_ip_req_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_ip_req_log ALTER COLUMN id SET DEFAULT nextval('public.mgt_acl_ip_req_log_id_seq'::regclass);


--
-- Name: mgt_alarm id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_alarm ALTER COLUMN id SET DEFAULT nextval('public.mgt_alarm_id_seq'::regclass);


--
-- Name: mgt_anti_tamper id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_anti_tamper ALTER COLUMN id SET DEFAULT nextval('public.mgt_anti_tamper_id_seq'::regclass);


--
-- Name: mgt_api id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_api ALTER COLUMN id SET DEFAULT nextval('public.mgt_api_id_seq'::regclass);


--
-- Name: mgt_api_asset id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_api_asset ALTER COLUMN id SET DEFAULT nextval('public.mgt_api_asset_id_seq'::regclass);


--
-- Name: mgt_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_audit_log ALTER COLUMN id SET DEFAULT nextval('public.mgt_audit_log_id_seq'::regclass);


--
-- Name: mgt_auth_defense id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_id_seq'::regclass);


--
-- Name: mgt_auth_defense_blocked_ip id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_blocked_ip ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_blocked_ip_id_seq'::regclass);


--
-- Name: mgt_auth_defense_source id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_source ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_source_id_seq'::regclass);


--
-- Name: mgt_auth_defense_source_user id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_source_user ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_source_user_id_seq'::regclass);


--
-- Name: mgt_auth_defense_user id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_user_id_seq'::regclass);


--
-- Name: mgt_auth_defense_user_bind id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_bind ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_user_bind_id_seq'::regclass);


--
-- Name: mgt_auth_defense_user_review id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_review ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_user_review_id_seq'::regclass);


--
-- Name: mgt_auth_defense_user_site id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_site ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_user_site_id_seq'::regclass);


--
-- Name: mgt_auth_defense_verify id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_verify ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_defense_verify_id_seq'::regclass);


--
-- Name: mgt_auth_token id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_token ALTER COLUMN id SET DEFAULT nextval('public.mgt_auth_token_id_seq'::regclass);


--
-- Name: mgt_behaviour id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_behaviour ALTER COLUMN id SET DEFAULT nextval('public.mgt_behaviour_id_seq'::regclass);


--
-- Name: mgt_challenge id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge ALTER COLUMN id SET DEFAULT nextval('public.mgt_challenge_id_seq'::regclass);


--
-- Name: mgt_challenge_blocked_ip id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge_blocked_ip ALTER COLUMN id SET DEFAULT nextval('public.mgt_challenge_blocked_ip_id_seq'::regclass);


--
-- Name: mgt_challenge_session id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge_session ALTER COLUMN id SET DEFAULT nextval('public.mgt_challenge_session_id_seq'::regclass);


--
-- Name: mgt_chaos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_chaos ALTER COLUMN id SET DEFAULT nextval('public.mgt_chaos_id_seq'::regclass);


--
-- Name: mgt_chaos_cnt id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_chaos_cnt ALTER COLUMN id SET DEFAULT nextval('public.mgt_chaos_cnt_id_seq'::regclass);


--
-- Name: mgt_cloud_policy id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_cloud_policy ALTER COLUMN id SET DEFAULT nextval('public.mgt_cloud_policy_id_seq'::regclass);


--
-- Name: mgt_detect_log_basic id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_detect_log_basic ALTER COLUMN id SET DEFAULT nextval('public.mgt_detect_log_basic_id_seq'::regclass);


--
-- Name: mgt_detect_log_detail id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_detect_log_detail ALTER COLUMN id SET DEFAULT nextval('public.mgt_detect_log_detail_id_seq'::regclass);


--
-- Name: mgt_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_event ALTER COLUMN id SET DEFAULT nextval('public.mgt_event_id_seq'::regclass);


--
-- Name: mgt_forwarding_rule id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_forwarding_rule ALTER COLUMN id SET DEFAULT nextval('public.mgt_forwarding_rule_id_seq'::regclass);


--
-- Name: mgt_fsl_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_fsl_history ALTER COLUMN id SET DEFAULT nextval('public.mgt_fsl_history_id_seq'::regclass);


--
-- Name: mgt_interest_point id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_interest_point ALTER COLUMN id SET DEFAULT nextval('public.mgt_interest_point_id_seq'::regclass);


--
-- Name: mgt_ip_group id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ip_group ALTER COLUMN id SET DEFAULT nextval('public.mgt_ip_group_id_seq'::regclass);


--
-- Name: mgt_ja4_library id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ja4_library ALTER COLUMN id SET DEFAULT nextval('public.mgt_ja4_library_id_seq'::regclass);


--
-- Name: mgt_lock id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_lock ALTER COLUMN id SET DEFAULT nextval('public.mgt_lock_id_seq'::regclass);


--
-- Name: mgt_master_sync_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_master_sync_event ALTER COLUMN id SET DEFAULT nextval('public.mgt_master_sync_event_id_seq'::regclass);


--
-- Name: mgt_node_key id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_node_key ALTER COLUMN id SET DEFAULT nextval('public.mgt_node_key_id_seq'::regclass);


--
-- Name: mgt_options id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_options ALTER COLUMN id SET DEFAULT nextval('public.mgt_options_id_seq'::regclass);


--
-- Name: mgt_policy id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_policy ALTER COLUMN id SET DEFAULT nextval('public.mgt_policy_id_seq'::regclass);


--
-- Name: mgt_policy_rule id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_policy_rule ALTER COLUMN id SET DEFAULT nextval('public.mgt_policy_rule_id_seq'::regclass);


--
-- Name: mgt_proxy_config id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_proxy_config ALTER COLUMN id SET DEFAULT nextval('public.mgt_proxy_config_id_seq'::regclass);


--
-- Name: mgt_report id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_report ALTER COLUMN id SET DEFAULT nextval('public.mgt_report_id_seq'::regclass);


--
-- Name: mgt_rule_detect_log_basic id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_detect_log_basic ALTER COLUMN id SET DEFAULT nextval('public.mgt_rule_detect_log_basic_id_seq'::regclass);


--
-- Name: mgt_rule_detect_log_detail id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_detect_log_detail ALTER COLUMN id SET DEFAULT nextval('public.mgt_rule_detect_log_detail_id_seq'::regclass);


--
-- Name: mgt_rule_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_event ALTER COLUMN id SET DEFAULT nextval('public.mgt_rule_event_id_seq'::regclass);


--
-- Name: mgt_security_posture id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_security_posture ALTER COLUMN id SET DEFAULT nextval('public.mgt_security_posture_id_seq'::regclass);


--
-- Name: mgt_skynet_moudle id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_skynet_moudle ALTER COLUMN id SET DEFAULT nextval('public.mgt_skynet_moudle_id_seq'::regclass);


--
-- Name: mgt_ssl_cert id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ssl_cert ALTER COLUMN id SET DEFAULT nextval('public.mgt_ssl_cert_id_seq'::regclass);


--
-- Name: mgt_statistics_agg id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_statistics_agg ALTER COLUMN id SET DEFAULT nextval('public.mgt_statistics_agg_id_seq'::regclass);


--
-- Name: mgt_sync_client id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_client ALTER COLUMN id SET DEFAULT nextval('public.mgt_sync_client_id_seq'::regclass);


--
-- Name: mgt_sync_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_log ALTER COLUMN id SET DEFAULT nextval('public.mgt_sync_log_id_seq'::regclass);


--
-- Name: mgt_sync_static_task id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_static_task ALTER COLUMN id SET DEFAULT nextval('public.mgt_sync_static_task_id_seq'::regclass);


--
-- Name: mgt_sync_table id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_table ALTER COLUMN id SET DEFAULT nextval('public.mgt_sync_table_id_seq'::regclass);


--
-- Name: mgt_sync_task id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_task ALTER COLUMN id SET DEFAULT nextval('public.mgt_sync_task_id_seq'::regclass);


--
-- Name: mgt_system_statistics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_system_statistics ALTER COLUMN id SET DEFAULT nextval('public.mgt_system_statistics_id_seq'::regclass);


--
-- Name: mgt_user id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_user ALTER COLUMN id SET DEFAULT nextval('public.mgt_user_id_seq'::regclass);


--
-- Name: mgt_user_lock id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_user_lock ALTER COLUMN id SET DEFAULT nextval('public.mgt_user_lock_id_seq'::regclass);


--
-- Name: mgt_waiting_room id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_waiting_room ALTER COLUMN id SET DEFAULT nextval('public.mgt_waiting_room_id_seq'::regclass);


--
-- Name: mgt_website id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_website ALTER COLUMN id SET DEFAULT nextval('public.mgt_website_id_seq'::regclass);


--
-- Name: mgt_website_group id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_website_group ALTER COLUMN id SET DEFAULT nextval('public.mgt_website_group_id_seq'::regclass);


--
-- Name: mgt_wr_stat_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_wr_stat_log ALTER COLUMN id SET DEFAULT nextval('public.mgt_wr_stat_log_id_seq'::regclass);


--
-- Name: policy_records id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_records ALTER COLUMN id SET DEFAULT nextval('public.policy_records_id_seq'::regclass);


--
-- Name: qps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.qps ALTER COLUMN id SET DEFAULT nextval('public.qps_id_seq'::regclass);


--
-- Name: resources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources ALTER COLUMN id SET DEFAULT nextval('public.resources_id_seq'::regclass);


--
-- Name: sites id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sites ALTER COLUMN id SET DEFAULT nextval('public.sites_id_seq'::regclass);


--
-- Name: statistics_basics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_basics ALTER COLUMN id SET DEFAULT nextval('public.statistics_basics_id_seq'::regclass);


--
-- Name: statistics_geos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_geos ALTER COLUMN id SET DEFAULT nextval('public.statistics_geos_id_seq'::regclass);


--
-- Name: statistics_ips id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_ips ALTER COLUMN id SET DEFAULT nextval('public.statistics_ips_id_seq'::regclass);


--
-- Name: statistics_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_sessions ALTER COLUMN id SET DEFAULT nextval('public.statistics_sessions_id_seq'::regclass);


--
-- Name: mgt_acl_blocked_ip mgt_acl_blocked_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_blocked_ip
    ADD CONSTRAINT mgt_acl_blocked_ip_pkey PRIMARY KEY (id);


--
-- Name: mgt_acl_config_v2 mgt_acl_config_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_config_v2
    ADD CONSTRAINT mgt_acl_config_v2_pkey PRIMARY KEY (id);


--
-- Name: mgt_acl_config_v3 mgt_acl_config_v3_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_config_v3
    ADD CONSTRAINT mgt_acl_config_v3_pkey PRIMARY KEY (id);


--
-- Name: mgt_acl_ip_req_log mgt_acl_ip_req_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_acl_ip_req_log
    ADD CONSTRAINT mgt_acl_ip_req_log_pkey PRIMARY KEY (id);


--
-- Name: mgt_alarm mgt_alarm_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_alarm
    ADD CONSTRAINT mgt_alarm_pkey PRIMARY KEY (id);


--
-- Name: mgt_anti_tamper mgt_anti_tamper_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_anti_tamper
    ADD CONSTRAINT mgt_anti_tamper_pkey PRIMARY KEY (id);


--
-- Name: mgt_api_asset mgt_api_asset_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_api_asset
    ADD CONSTRAINT mgt_api_asset_pkey PRIMARY KEY (id);


--
-- Name: mgt_api mgt_api_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_api
    ADD CONSTRAINT mgt_api_pkey PRIMARY KEY (id);


--
-- Name: mgt_audit_log mgt_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_audit_log
    ADD CONSTRAINT mgt_audit_log_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_blocked_ip mgt_auth_defense_blocked_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_blocked_ip
    ADD CONSTRAINT mgt_auth_defense_blocked_ip_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense mgt_auth_defense_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense
    ADD CONSTRAINT mgt_auth_defense_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_source mgt_auth_defense_source_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_source
    ADD CONSTRAINT mgt_auth_defense_source_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_source_user mgt_auth_defense_source_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_source_user
    ADD CONSTRAINT mgt_auth_defense_source_user_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_user_bind mgt_auth_defense_user_bind_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_bind
    ADD CONSTRAINT mgt_auth_defense_user_bind_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_user mgt_auth_defense_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user
    ADD CONSTRAINT mgt_auth_defense_user_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_user_review mgt_auth_defense_user_review_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_review
    ADD CONSTRAINT mgt_auth_defense_user_review_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_user_site mgt_auth_defense_user_site_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_user_site
    ADD CONSTRAINT mgt_auth_defense_user_site_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_defense_verify mgt_auth_defense_verify_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_defense_verify
    ADD CONSTRAINT mgt_auth_defense_verify_pkey PRIMARY KEY (id);


--
-- Name: mgt_auth_token mgt_auth_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_auth_token
    ADD CONSTRAINT mgt_auth_token_pkey PRIMARY KEY (id);


--
-- Name: mgt_behaviour mgt_behaviour_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_behaviour
    ADD CONSTRAINT mgt_behaviour_pkey PRIMARY KEY (id);


--
-- Name: mgt_challenge_blocked_ip mgt_challenge_blocked_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge_blocked_ip
    ADD CONSTRAINT mgt_challenge_blocked_ip_pkey PRIMARY KEY (id);


--
-- Name: mgt_challenge mgt_challenge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge
    ADD CONSTRAINT mgt_challenge_pkey PRIMARY KEY (id);


--
-- Name: mgt_challenge_session mgt_challenge_session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_challenge_session
    ADD CONSTRAINT mgt_challenge_session_pkey PRIMARY KEY (id);


--
-- Name: mgt_chaos_cnt mgt_chaos_cnt_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_chaos_cnt
    ADD CONSTRAINT mgt_chaos_cnt_pkey PRIMARY KEY (id);


--
-- Name: mgt_chaos mgt_chaos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_chaos
    ADD CONSTRAINT mgt_chaos_pkey PRIMARY KEY (id);


--
-- Name: mgt_cloud_policy mgt_cloud_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_cloud_policy
    ADD CONSTRAINT mgt_cloud_policy_pkey PRIMARY KEY (id);


--
-- Name: mgt_detect_log_basic mgt_detect_log_basic_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_detect_log_basic
    ADD CONSTRAINT mgt_detect_log_basic_pkey PRIMARY KEY (id);


--
-- Name: mgt_detect_log_detail mgt_detect_log_detail_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_detect_log_detail
    ADD CONSTRAINT mgt_detect_log_detail_pkey PRIMARY KEY (id);


--
-- Name: mgt_event mgt_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_event
    ADD CONSTRAINT mgt_event_pkey PRIMARY KEY (id);


--
-- Name: mgt_forwarding_rule mgt_forwarding_rule_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_forwarding_rule
    ADD CONSTRAINT mgt_forwarding_rule_pkey PRIMARY KEY (id);


--
-- Name: mgt_fsl_history mgt_fsl_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_fsl_history
    ADD CONSTRAINT mgt_fsl_history_pkey PRIMARY KEY (id);


--
-- Name: mgt_interest_point mgt_interest_point_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_interest_point
    ADD CONSTRAINT mgt_interest_point_pkey PRIMARY KEY (id);


--
-- Name: mgt_ip_group mgt_ip_group_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ip_group
    ADD CONSTRAINT mgt_ip_group_pkey PRIMARY KEY (id);


--
-- Name: mgt_ja4_library mgt_ja4_library_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ja4_library
    ADD CONSTRAINT mgt_ja4_library_pkey PRIMARY KEY (id);


--
-- Name: mgt_lock mgt_lock_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_lock
    ADD CONSTRAINT mgt_lock_key_key UNIQUE (key);


--
-- Name: mgt_lock mgt_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_lock
    ADD CONSTRAINT mgt_lock_pkey PRIMARY KEY (id);


--
-- Name: mgt_master_sync_event mgt_master_sync_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_master_sync_event
    ADD CONSTRAINT mgt_master_sync_event_pkey PRIMARY KEY (id);


--
-- Name: mgt_node_key mgt_node_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_node_key
    ADD CONSTRAINT mgt_node_key_pkey PRIMARY KEY (id);


--
-- Name: mgt_options mgt_options_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_options
    ADD CONSTRAINT mgt_options_pkey PRIMARY KEY (id);


--
-- Name: mgt_policy mgt_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_policy
    ADD CONSTRAINT mgt_policy_pkey PRIMARY KEY (id);


--
-- Name: mgt_policy_rule mgt_policy_rule_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_policy_rule
    ADD CONSTRAINT mgt_policy_rule_pkey PRIMARY KEY (id);


--
-- Name: mgt_proxy_config mgt_proxy_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_proxy_config
    ADD CONSTRAINT mgt_proxy_config_pkey PRIMARY KEY (id);


--
-- Name: mgt_report mgt_report_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_report
    ADD CONSTRAINT mgt_report_pkey PRIMARY KEY (id);


--
-- Name: mgt_rule_detect_log_basic mgt_rule_detect_log_basic_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_detect_log_basic
    ADD CONSTRAINT mgt_rule_detect_log_basic_pkey PRIMARY KEY (id);


--
-- Name: mgt_rule_detect_log_detail mgt_rule_detect_log_detail_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_detect_log_detail
    ADD CONSTRAINT mgt_rule_detect_log_detail_pkey PRIMARY KEY (id);


--
-- Name: mgt_rule_event mgt_rule_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_rule_event
    ADD CONSTRAINT mgt_rule_event_pkey PRIMARY KEY (id);


--
-- Name: mgt_security_posture mgt_security_posture_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_security_posture
    ADD CONSTRAINT mgt_security_posture_pkey PRIMARY KEY (id);


--
-- Name: mgt_share_plan_v2_config mgt_share_plan_v2_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_share_plan_v2_config
    ADD CONSTRAINT mgt_share_plan_v2_config_pkey PRIMARY KEY (id);


--
-- Name: mgt_skynet_moudle mgt_skynet_moudle_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_skynet_moudle
    ADD CONSTRAINT mgt_skynet_moudle_pkey PRIMARY KEY (id);


--
-- Name: mgt_ssl_cert mgt_ssl_cert_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_ssl_cert
    ADD CONSTRAINT mgt_ssl_cert_pkey PRIMARY KEY (id);


--
-- Name: mgt_statistics_agg mgt_statistics_agg_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_statistics_agg
    ADD CONSTRAINT mgt_statistics_agg_pkey PRIMARY KEY (id);


--
-- Name: mgt_sync_client mgt_sync_client_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_client
    ADD CONSTRAINT mgt_sync_client_pkey PRIMARY KEY (id);


--
-- Name: mgt_sync_log mgt_sync_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_log
    ADD CONSTRAINT mgt_sync_log_pkey PRIMARY KEY (id);


--
-- Name: mgt_sync_static_task mgt_sync_static_task_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_static_task
    ADD CONSTRAINT mgt_sync_static_task_pkey PRIMARY KEY (id);


--
-- Name: mgt_sync_table mgt_sync_table_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_table
    ADD CONSTRAINT mgt_sync_table_pkey PRIMARY KEY (id);


--
-- Name: mgt_sync_task mgt_sync_task_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_sync_task
    ADD CONSTRAINT mgt_sync_task_pkey PRIMARY KEY (id);


--
-- Name: mgt_system_statistics mgt_system_statistics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_system_statistics
    ADD CONSTRAINT mgt_system_statistics_pkey PRIMARY KEY (id);


--
-- Name: mgt_user_lock mgt_user_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_user_lock
    ADD CONSTRAINT mgt_user_lock_pkey PRIMARY KEY (id);


--
-- Name: mgt_user mgt_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_user
    ADD CONSTRAINT mgt_user_pkey PRIMARY KEY (id);


--
-- Name: mgt_waiting_room mgt_waiting_room_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_waiting_room
    ADD CONSTRAINT mgt_waiting_room_pkey PRIMARY KEY (id);


--
-- Name: mgt_website_group mgt_website_group_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_website_group
    ADD CONSTRAINT mgt_website_group_pkey PRIMARY KEY (id);


--
-- Name: mgt_website mgt_website_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_website
    ADD CONSTRAINT mgt_website_pkey PRIMARY KEY (id);


--
-- Name: mgt_wr_stat_log mgt_wr_stat_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mgt_wr_stat_log
    ADD CONSTRAINT mgt_wr_stat_log_pkey PRIMARY KEY (id);


--
-- Name: policy_records policy_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_records
    ADD CONSTRAINT policy_records_pkey PRIMARY KEY (id);


--
-- Name: qps qps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.qps
    ADD CONSTRAINT qps_pkey PRIMARY KEY (id);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sites sites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sites
    ADD CONSTRAINT sites_pkey PRIMARY KEY (id);


--
-- Name: statistics_basics statistics_basics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_basics
    ADD CONSTRAINT statistics_basics_pkey PRIMARY KEY (id);


--
-- Name: statistics_geos statistics_geos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_geos
    ADD CONSTRAINT statistics_geos_pkey PRIMARY KEY (id);


--
-- Name: statistics_ips statistics_ips_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_ips
    ADD CONSTRAINT statistics_ips_pkey PRIMARY KEY (id);


--
-- Name: statistics_sessions statistics_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.statistics_sessions
    ADD CONSTRAINT statistics_sessions_pkey PRIMARY KEY (id);


--
-- Name: idx_auth_defense_user_site_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_defense_user_site_user_id ON public.mgt_auth_defense_user_review USING btree (site_id, auth_user_id);


--
-- Name: idx_detect_log_basic_src_ip_host_dst_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detect_log_basic_src_ip_host_dst_port ON public.mgt_detect_log_basic USING btree (src_ip, "left"(host, 256), dst_port);


--
-- Name: idx_interest_point_source_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_interest_point_source_type ON public.mgt_interest_point USING btree (source, type);


--
-- Name: idx_mgt_acl_blocked_ip_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_created_at ON public.mgt_acl_blocked_ip USING btree (created_at);


--
-- Name: idx_mgt_acl_blocked_ip_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_ip ON public.mgt_acl_blocked_ip USING btree (ip);


--
-- Name: idx_mgt_acl_blocked_ip_query_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_query_key ON public.mgt_acl_blocked_ip USING btree (query_key);


--
-- Name: idx_mgt_acl_blocked_ip_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_site_id ON public.mgt_acl_blocked_ip USING btree (site_id);


--
-- Name: idx_mgt_acl_blocked_ip_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_status ON public.mgt_acl_blocked_ip USING btree (status);


--
-- Name: idx_mgt_acl_blocked_ip_valid_before; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_blocked_ip_valid_before ON public.mgt_acl_blocked_ip USING btree (valid_before);


--
-- Name: idx_mgt_acl_config_v2_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v2_site_id ON public.mgt_acl_config_v2 USING btree (site_id);


--
-- Name: idx_mgt_acl_config_v2_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v2_updated_at ON public.mgt_acl_config_v2 USING btree (updated_at);


--
-- Name: idx_mgt_acl_config_v3_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_action ON public.mgt_acl_config_v3 USING btree (action);


--
-- Name: idx_mgt_acl_config_v3_block_min; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_block_min ON public.mgt_acl_config_v3 USING btree (block_min);


--
-- Name: idx_mgt_acl_config_v3_built_in; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_built_in ON public.mgt_acl_config_v3 USING btree (built_in);


--
-- Name: idx_mgt_acl_config_v3_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_count ON public.mgt_acl_config_v3 USING btree (count);


--
-- Name: idx_mgt_acl_config_v3_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_enabled ON public.mgt_acl_config_v3 USING btree (enabled);


--
-- Name: idx_mgt_acl_config_v3_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_name ON public.mgt_acl_config_v3 USING btree (name);


--
-- Name: idx_mgt_acl_config_v3_period; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_period ON public.mgt_acl_config_v3 USING btree (period);


--
-- Name: idx_mgt_acl_config_v3_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_priority ON public.mgt_acl_config_v3 USING btree (priority);


--
-- Name: idx_mgt_acl_config_v3_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_site_id ON public.mgt_acl_config_v3 USING btree (site_id);


--
-- Name: idx_mgt_acl_config_v3_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_type ON public.mgt_acl_config_v3 USING btree (type);


--
-- Name: idx_mgt_acl_config_v3_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_updated_at ON public.mgt_acl_config_v3 USING btree (updated_at);


--
-- Name: idx_mgt_acl_config_v3_use_global; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_config_v3_use_global ON public.mgt_acl_config_v3 USING btree (use_global);


--
-- Name: idx_mgt_acl_ip_req_log_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_ip_req_log_action ON public.mgt_acl_ip_req_log USING btree (action);


--
-- Name: idx_mgt_acl_ip_req_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_ip_req_log_created_at ON public.mgt_acl_ip_req_log USING btree (created_at);


--
-- Name: idx_mgt_acl_ip_req_log_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_acl_ip_req_log_ip ON public.mgt_acl_ip_req_log USING btree (ip);


--
-- Name: idx_mgt_alarm_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_alarm_updated_at ON public.mgt_alarm USING btree (updated_at);


--
-- Name: idx_mgt_anti_tamper_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_anti_tamper_updated_at ON public.mgt_anti_tamper USING btree (updated_at);


--
-- Name: idx_mgt_api_asset_site_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_api_asset_site_uuid ON public.mgt_api_asset USING btree (site_uuid);


--
-- Name: idx_mgt_api_asset_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_api_asset_uuid ON public.mgt_api_asset USING btree (uuid);


--
-- Name: idx_mgt_auth_defense_blocked_ip_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_blocked_ip_created_at ON public.mgt_auth_defense_blocked_ip USING btree (created_at);


--
-- Name: idx_mgt_auth_defense_blocked_ip_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_blocked_ip_event_id ON public.mgt_auth_defense_blocked_ip USING btree (event_id);


--
-- Name: idx_mgt_auth_defense_blocked_ip_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_blocked_ip_ip ON public.mgt_auth_defense_blocked_ip USING btree (ip);


--
-- Name: idx_mgt_auth_defense_blocked_ip_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_blocked_ip_rule_id ON public.mgt_auth_defense_blocked_ip USING btree (rule_id);


--
-- Name: idx_mgt_auth_defense_blocked_ip_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_blocked_ip_site_id ON public.mgt_auth_defense_blocked_ip USING btree (site_id);


--
-- Name: idx_mgt_auth_defense_source_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_source_updated_at ON public.mgt_auth_defense_source USING btree (updated_at);


--
-- Name: idx_mgt_auth_defense_user_bind_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_user_bind_updated_at ON public.mgt_auth_defense_user_bind USING btree (updated_at);


--
-- Name: idx_mgt_auth_defense_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_user_email ON public.mgt_auth_defense_user USING btree (email);


--
-- Name: idx_mgt_auth_defense_user_phone; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_user_phone ON public.mgt_auth_defense_user USING btree (phone);


--
-- Name: idx_mgt_auth_defense_user_review_request_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_user_review_request_time ON public.mgt_auth_defense_user_review USING btree (request_time);


--
-- Name: idx_mgt_auth_defense_user_review_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_user_review_updated_at ON public.mgt_auth_defense_user_review USING btree (updated_at);


--
-- Name: idx_mgt_auth_defense_user_review_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_user_review_uuid ON public.mgt_auth_defense_user_review USING btree (uuid);


--
-- Name: idx_mgt_auth_defense_user_site_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_user_site_updated_at ON public.mgt_auth_defense_user_site USING btree (updated_at);


--
-- Name: idx_mgt_auth_defense_user_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_user_updated_at ON public.mgt_auth_defense_user USING btree (updated_at);


--
-- Name: idx_mgt_auth_defense_user_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_user_username ON public.mgt_auth_defense_user USING btree (username);


--
-- Name: idx_mgt_auth_defense_verify_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_verify_created_at ON public.mgt_auth_defense_verify USING btree (created_at);


--
-- Name: idx_mgt_auth_defense_verify_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_verify_ip ON public.mgt_auth_defense_verify USING btree (ip);


--
-- Name: idx_mgt_auth_defense_verify_third_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_verify_third_id ON public.mgt_auth_defense_verify USING btree (third_id);


--
-- Name: idx_mgt_auth_defense_verify_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_auth_defense_verify_user_id ON public.mgt_auth_defense_verify USING btree (user_id);


--
-- Name: idx_mgt_auth_defense_verify_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_auth_defense_verify_uuid ON public.mgt_auth_defense_verify USING btree (uuid);


--
-- Name: idx_mgt_challenge_blocked_ip_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_blocked_ip_created_at ON public.mgt_challenge_blocked_ip USING btree (created_at);


--
-- Name: idx_mgt_challenge_blocked_ip_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_challenge_blocked_ip_event_id ON public.mgt_challenge_blocked_ip USING btree (event_id);


--
-- Name: idx_mgt_challenge_blocked_ip_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_blocked_ip_ip ON public.mgt_challenge_blocked_ip USING btree (ip);


--
-- Name: idx_mgt_challenge_blocked_ip_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_blocked_ip_rule_id ON public.mgt_challenge_blocked_ip USING btree (rule_id);


--
-- Name: idx_mgt_challenge_blocked_ip_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_blocked_ip_site_id ON public.mgt_challenge_blocked_ip USING btree (site_id);


--
-- Name: idx_mgt_challenge_session_deadline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_session_deadline ON public.mgt_challenge_session USING btree (deadline);


--
-- Name: idx_mgt_challenge_session_session; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_challenge_session_session ON public.mgt_challenge_session USING btree (session);


--
-- Name: idx_mgt_challenge_session_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_challenge_session_updated_at ON public.mgt_challenge_session USING btree (updated_at);


--
-- Name: idx_mgt_chaos_cnt_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_chaos_cnt_date ON public.mgt_chaos_cnt USING btree (date);


--
-- Name: idx_mgt_chaos_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_chaos_updated_at ON public.mgt_chaos USING btree (updated_at);


--
-- Name: idx_mgt_chaos_website_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_chaos_website_id ON public.mgt_chaos USING btree (website_id);


--
-- Name: idx_mgt_cloud_policy_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_cloud_policy_updated_at ON public.mgt_cloud_policy USING btree (updated_at);


--
-- Name: idx_mgt_detect_log_basic_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_action ON public.mgt_detect_log_basic USING btree (action);


--
-- Name: idx_mgt_detect_log_basic_attack_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_attack_type ON public.mgt_detect_log_basic USING btree (attack_type);


--
-- Name: idx_mgt_detect_log_basic_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_created_at ON public.mgt_detect_log_basic USING btree (created_at);


--
-- Name: idx_mgt_detect_log_basic_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_detect_log_basic_event_id ON public.mgt_detect_log_basic USING btree (event_id);


--
-- Name: idx_mgt_detect_log_basic_risk_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_risk_level ON public.mgt_detect_log_basic USING btree (risk_level);


--
-- Name: idx_mgt_detect_log_basic_socket_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_socket_ip ON public.mgt_detect_log_basic USING btree (socket_ip);


--
-- Name: idx_mgt_detect_log_basic_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_basic_timestamp ON public.mgt_detect_log_basic USING btree ("timestamp");


--
-- Name: idx_mgt_detect_log_detail_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_detect_log_detail_event_id ON public.mgt_detect_log_detail USING btree (event_id);


--
-- Name: idx_mgt_detect_log_detail_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_detect_log_detail_timestamp ON public.mgt_detect_log_detail USING btree ("timestamp");


--
-- Name: idx_mgt_event_dst_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_event_dst_port ON public.mgt_event USING btree (dst_port);


--
-- Name: idx_mgt_event_finished; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_event_finished ON public.mgt_event USING btree (finished);


--
-- Name: idx_mgt_event_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_event_host ON public.mgt_event USING btree (host);


--
-- Name: idx_mgt_event_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_event_ip ON public.mgt_event USING btree (ip);


--
-- Name: idx_mgt_event_site_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_event_site_uuid ON public.mgt_event USING btree (site_uuid);


--
-- Name: idx_mgt_forwarding_rule_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_forwarding_rule_site_id ON public.mgt_forwarding_rule USING btree (site_id);


--
-- Name: idx_mgt_forwarding_rule_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_forwarding_rule_updated_at ON public.mgt_forwarding_rule USING btree (updated_at);


--
-- Name: idx_mgt_fsl_history_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_fsl_history_hash ON public.mgt_fsl_history USING btree (hash);


--
-- Name: idx_mgt_ip_group_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_ip_group_reference ON public.mgt_ip_group USING btree (reference);


--
-- Name: idx_mgt_ip_group_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_ip_group_updated_at ON public.mgt_ip_group USING btree (updated_at);


--
-- Name: idx_mgt_ja4_library_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_ja4_library_updated_at ON public.mgt_ja4_library USING btree (updated_at);


--
-- Name: idx_mgt_master_sync_event_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_master_sync_event_updated_at ON public.mgt_master_sync_event USING btree (updated_at);


--
-- Name: idx_mgt_master_sync_event_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_master_sync_event_uuid ON public.mgt_master_sync_event USING btree (uuid);


--
-- Name: idx_mgt_node_key_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_node_key_fingerprint ON public.mgt_node_key USING btree (fingerprint);


--
-- Name: idx_mgt_node_key_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_node_key_updated_at ON public.mgt_node_key USING btree (updated_at);


--
-- Name: idx_mgt_node_key_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_node_key_uuid ON public.mgt_node_key USING btree (uuid);


--
-- Name: idx_mgt_options_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_options_key ON public.mgt_options USING btree (key);


--
-- Name: idx_mgt_options_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_options_updated_at ON public.mgt_options USING btree (updated_at);


--
-- Name: idx_mgt_policy_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_policy_parent_id ON public.mgt_policy USING btree (parent_id);


--
-- Name: idx_mgt_policy_rule_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_policy_rule_updated_at ON public.mgt_policy_rule USING btree (updated_at);


--
-- Name: idx_mgt_policy_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_policy_updated_at ON public.mgt_policy USING btree (updated_at);


--
-- Name: idx_mgt_proxy_config_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_proxy_config_site_id ON public.mgt_proxy_config USING btree (site_id);


--
-- Name: idx_mgt_proxy_config_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_proxy_config_updated_at ON public.mgt_proxy_config USING btree (updated_at);


--
-- Name: idx_mgt_rule_detect_log_basic_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_action ON public.mgt_rule_detect_log_basic USING btree (action);


--
-- Name: idx_mgt_rule_detect_log_basic_attack_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_attack_type ON public.mgt_rule_detect_log_basic USING btree (attack_type);


--
-- Name: idx_mgt_rule_detect_log_basic_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_created_at ON public.mgt_rule_detect_log_basic USING btree (created_at);


--
-- Name: idx_mgt_rule_detect_log_basic_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_rule_detect_log_basic_event_id ON public.mgt_rule_detect_log_basic USING btree (event_id);


--
-- Name: idx_mgt_rule_detect_log_basic_policy_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_policy_rule_id ON public.mgt_rule_detect_log_basic USING btree (policy_rule_id);


--
-- Name: idx_mgt_rule_detect_log_basic_policy_rule_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_policy_rule_parent_id ON public.mgt_rule_detect_log_basic USING btree (policy_rule_parent_id);


--
-- Name: idx_mgt_rule_detect_log_basic_risk_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_risk_level ON public.mgt_rule_detect_log_basic USING btree (risk_level);


--
-- Name: idx_mgt_rule_detect_log_basic_socket_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_socket_ip ON public.mgt_rule_detect_log_basic USING btree (socket_ip);


--
-- Name: idx_mgt_rule_detect_log_basic_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_basic_timestamp ON public.mgt_rule_detect_log_basic USING btree ("timestamp");


--
-- Name: idx_mgt_rule_detect_log_detail_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_rule_detect_log_detail_event_id ON public.mgt_rule_detect_log_detail USING btree (event_id);


--
-- Name: idx_mgt_rule_detect_log_detail_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_detect_log_detail_timestamp ON public.mgt_rule_detect_log_detail USING btree ("timestamp");


--
-- Name: idx_mgt_rule_event_dst_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_event_dst_port ON public.mgt_rule_event USING btree (dst_port);


--
-- Name: idx_mgt_rule_event_finished; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_event_finished ON public.mgt_rule_event USING btree (finished);


--
-- Name: idx_mgt_rule_event_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_event_host ON public.mgt_rule_event USING btree (host);


--
-- Name: idx_mgt_rule_event_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_event_ip ON public.mgt_rule_event USING btree (ip);


--
-- Name: idx_mgt_rule_event_site_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_rule_event_site_uuid ON public.mgt_rule_event USING btree (site_uuid);


--
-- Name: idx_mgt_security_posture_day_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_security_posture_day_timestamp ON public.mgt_security_posture USING btree (day_timestamp);


--
-- Name: idx_mgt_security_posture_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_security_posture_timestamp ON public.mgt_security_posture USING btree ("timestamp");


--
-- Name: idx_mgt_skynet_moudle_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_skynet_moudle_updated_at ON public.mgt_skynet_moudle USING btree (updated_at);


--
-- Name: idx_mgt_ssl_cert_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_ssl_cert_updated_at ON public.mgt_ssl_cert USING btree (updated_at);


--
-- Name: idx_mgt_statistics_agg_day_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_statistics_agg_day_time ON public.mgt_statistics_agg USING btree (day_time);


--
-- Name: idx_mgt_statistics_agg_hour_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_statistics_agg_hour_time ON public.mgt_statistics_agg USING btree (hour_time);


--
-- Name: idx_mgt_sync_client_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_sync_client_client_id ON public.mgt_sync_client USING btree (client_id);


--
-- Name: idx_mgt_sync_client_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_sync_client_token ON public.mgt_sync_client USING btree (token);


--
-- Name: idx_mgt_sync_table_client_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_sync_table_client_name ON public.mgt_sync_table USING btree (client_id, name);


--
-- Name: idx_mgt_sync_task_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_sync_task_client_id ON public.mgt_sync_task USING btree (client_id);


--
-- Name: idx_mgt_sync_task_client_table_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_sync_task_client_table_status ON public.mgt_sync_task USING btree (client_id, table_name, status);


--
-- Name: idx_mgt_sync_task_node; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_sync_task_node ON public.mgt_sync_task USING btree (node);


--
-- Name: idx_mgt_sync_task_task_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_sync_task_task_id ON public.mgt_sync_task USING btree (task_id);


--
-- Name: idx_mgt_system_statistics_city; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_city ON public.mgt_system_statistics USING btree (city);


--
-- Name: idx_mgt_system_statistics_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_country ON public.mgt_system_statistics USING btree (country);


--
-- Name: idx_mgt_system_statistics_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_created_at ON public.mgt_system_statistics USING btree (created_at);


--
-- Name: idx_mgt_system_statistics_province; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_province ON public.mgt_system_statistics USING btree (province);


--
-- Name: idx_mgt_system_statistics_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_type ON public.mgt_system_statistics USING btree (type);


--
-- Name: idx_mgt_system_statistics_website; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_system_statistics_website ON public.mgt_system_statistics USING btree (website);


--
-- Name: idx_mgt_user_lock_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_user_lock_username ON public.mgt_user_lock USING btree (username);


--
-- Name: idx_mgt_user_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_user_updated_at ON public.mgt_user USING btree (updated_at);


--
-- Name: idx_mgt_user_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_user_username ON public.mgt_user USING btree (username);


--
-- Name: idx_mgt_waiting_room_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_waiting_room_updated_at ON public.mgt_waiting_room USING btree (updated_at);


--
-- Name: idx_mgt_waiting_room_website_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_waiting_room_website_id ON public.mgt_waiting_room USING btree (website_id);


--
-- Name: idx_mgt_website_group_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_website_group_updated_at ON public.mgt_website_group USING btree (updated_at);


--
-- Name: idx_mgt_website_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_website_updated_at ON public.mgt_website USING btree (updated_at);


--
-- Name: idx_mgt_wr_stat_log_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mgt_wr_stat_log_event_id ON public.mgt_wr_stat_log USING btree (event_id);


--
-- Name: idx_mgt_wr_stat_log_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_wr_stat_log_rule_id ON public.mgt_wr_stat_log USING btree (rule_id);


--
-- Name: idx_mgt_wr_stat_log_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mgt_wr_stat_log_site_id ON public.mgt_wr_stat_log USING btree (site_id);


--
-- Name: idx_policy_cloud_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_policy_cloud_id ON public.mgt_policy USING btree (cloud_id) WHERE (cloud_id > 0);


--
-- Name: idx_resources_method; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_method ON public.resources USING btree (method);


--
-- Name: idx_resources_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_path ON public.resources USING btree (path);


--
-- Name: idx_resources_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_site_id ON public.resources USING btree (site_id);


--
-- Name: idx_resources_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resources_updated_at ON public.resources USING btree (updated_at);


--
-- Name: idx_site_path_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_site_path_prefix ON public.mgt_forwarding_rule USING btree (site_id, path_prefix);


--
-- Name: idx_sites_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_sites_site_id ON public.sites USING btree (site_id);


--
-- Name: idx_sites_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sites_updated_at ON public.sites USING btree (updated_at);


--
-- Name: idx_statistics_agg_type_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_agg_type_time ON public.mgt_statistics_agg USING btree (type, "time");


--
-- Name: idx_statistics_basic_type_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_basic_type_time ON public.statistics_basics USING btree (type, "time");


--
-- Name: idx_statistics_basics_site_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_basics_site_id ON public.statistics_basics USING btree (site_id);


--
-- Name: idx_statistics_geo_time_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_geo_time_country ON public.statistics_geos USING btree ("time", country);


--
-- Name: idx_statistics_ips_day_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_ips_day_time ON public.statistics_ips USING btree (day_time);


--
-- Name: idx_statistics_ips_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_ips_key ON public.statistics_ips USING btree (key);


--
-- Name: idx_statistics_ips_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_ips_time ON public.statistics_ips USING btree ("time");


--
-- Name: idx_statistics_sessions_day_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_sessions_day_time ON public.statistics_sessions USING btree (day_time);


--
-- Name: idx_statistics_sessions_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_sessions_key ON public.statistics_sessions USING btree (key);


--
-- Name: idx_statistics_sessions_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_statistics_sessions_time ON public.statistics_sessions USING btree ("time");


--
-- Name: siteid_path_method; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX siteid_path_method ON public.resources USING btree (site_id, path, method);


--
-- Name: type_createdat_locate; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX type_createdat_locate ON public.mgt_system_statistics USING btree (type, created_at, country, province, city);


--
-- Name: type_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX type_source_id ON public.mgt_system_statistics USING btree (type, created_at, source_id);


--
-- Name: type_website_createdat; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX type_website_createdat ON public.mgt_system_statistics USING btree (type, created_at, website);


--
-- Name: udx_api_path_time_frontend; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX udx_api_path_time_frontend ON public.mgt_api USING btree (path, "time", frontend);


--
-- Name: udx_auth_defense_source_user_source_id_uid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX udx_auth_defense_source_user_source_id_uid ON public.mgt_auth_defense_source_user USING btree (auth_source_id, uid);


--
-- Name: udx_auth_defense_user_site_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX udx_auth_defense_user_site_user_id ON public.mgt_auth_defense_user_site USING btree (site_id, auth_user_id);


--
-- Name: udx_policy_record_policy_id_site_id_time; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX udx_policy_record_policy_id_site_id_time ON public.policy_records USING btree ("time", site_id, policy_id);


--
-- Name: un_idx_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX un_idx_username ON public.mgt_user USING btree (username);


--
-- Name: unique_data; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_data ON public.mgt_acl_ip_req_log USING btree (created_at, ip, action);


--
-- PostgreSQL database dump complete
--

