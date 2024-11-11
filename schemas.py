from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    role = fields.Str(required=True)

class WorkSchema(Schema):
    id = fields.Int(dump_only=True)
    geo = fields.Str(required=True)
    work = fields.Str(required=True)
    sum = fields.Float(required=True)
    name = fields.Str(required=True)
    description = fields.Str(required=True)
    photo = fields.Str(required=True)
    created_at = fields.DateTime(dump_only=True)
