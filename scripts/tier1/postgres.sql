CREATE TABLE public.owners (
    id BIGINT NOT NULL,
    CONSTRAINT owners_pkey PRIMARY KEY (id)
);

COMMENT ON TABLE public.owners IS 'Tier-1 fixture owners';

CREATE TABLE public.items (
    id BIGINT NOT NULL,
    owner_id BIGINT,
    name VARCHAR(255) NOT NULL,
    qty BIGINT NOT NULL,
    metadata JSONB NOT NULL,
    payload TEXT,
    CONSTRAINT items_pkey PRIMARY KEY (id),
    CONSTRAINT items_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.owners (id),
    CONSTRAINT items_name_key UNIQUE (name)
);

COMMENT ON TABLE public.items IS 'Tier-1 fixture items';
COMMENT ON COLUMN public.items.id IS 'Tier-1 fixture item identifier';

CREATE INDEX items_qty_idx ON public.items (qty);

INSERT INTO public.owners (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;
