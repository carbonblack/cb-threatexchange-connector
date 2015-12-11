drop table if exists owners;
drop table if exists indicator_descriptors;
drop index if exists descriptor_id_index;
drop index if exists owner_id_index;
drop index if exists descriptor_time_index;

create table owners (
  id text primary key,
  name text,
  email text
);

create table indicator_descriptors (
  id text primary key,
  status text,
  indicator text,
  indicator_type text,
  severity text,
  last_updated timestamp,
  threat_type text,
  owner_id text,
  description text,
  share_level text,
  confidence integer,
  confidence_band text,

  FOREIGN KEY(owner_id) REFERENCES owners(id)
);

create unique index descriptor_id_index on indicator_descriptors(id);
create unique index owner_id_index on owners(id);
create index descriptor_time_index on indicator_descriptors(last_updated);
