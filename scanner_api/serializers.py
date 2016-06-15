from rest_framework import serializers
from scanner_api import models

class VulnSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Vuln
        fields = ('cveid', 'program_name', 'program_version', 'date',
                  'detail', 'simple_detail', 'concerned_cpe', 'score')

    def create(self, validated_data):
        return models.Vuln.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.cveid = validated_data.get('cveid', instance.cveid)
        instance.program_name = validated_data.get('program_name', instance.program_name)
        instance.program_version = validated_data.get('program_version', instance.program_version)
        instance.date = validated_data.get('date', instance.date)
        instance.detail = validated_data.get('detail', instance.detail)
        instance.simple_detail = validated_data.get('simple_detail', instance.simple_detail)
        instance.score = validated_data.get('score', instance.score)
        instance.save()
        return instance

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.User
        fields = ('id', 'username', 'email', 'password', 'user_type', 'contrat', 'id_dealer')

    def create(self, validated_data):

        data = {k:v for k, v in validated_data.items() if k != "password"}
        user = models.User.objects.create(**data)
        if "password" in validated_data:
            user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.id = validated_data.get('id', instance.id)
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.user_type = validated_data.get('user_type', instance.user_type)
        instance.contrat = validated_data.get('contrat', instance.contrat)
        instance.id_dealer = validated_data.get('id_dealer', instance.id_dealer)

        instance.set_password(validated_data['password'])
        instance.save()
        return instance

class UserProgramsSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.UserPrograms
        fields = ('program_name', 'program_version', 'minimum_score', 'user_id')

    def create(self, validated_data):
        return models.UserPrograms.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.id = validated_data.get('id', instance.id)
        instance.program_name = validated_data.get('program_name', instance.program_name)
        instance.program_version = validated_data.get('program_version', instance.program_version)
        instance.minimum_score = validated_data.get('minimum_score', instance.minimum_score)
        instance.user_id = validated_data.get('user_id', instance.user_id)
        instance.save()
        return instance

class AlertSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Alert
        fields = ('user', 'program', 'vuln')

    def create(self, validated_data):
        return models.Alert.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.id = validated_data.get('id', instance.id)
        instance.user = validated_data.get('user', instance.user)
        instance.program = validated_data.get('program', instance.program)
        instance.vuln = validated_data.get('vuln', instance.vuln)
        instance.save()
        return instance
