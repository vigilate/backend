from rest_framework import serializers
from vigilate_backend import models
from vulnerability_manager.serializers import CveSerializer

class UserSerializer(serializers.ModelSerializer):
    """Serialisation of User
    """

    class Meta:
        model = models.User
        fields = ('id', 'email', 'password', 'user_type', 'contrat', 'id_dealer', 'default_alert_type')

    def create(self, validated_data):
        """Create an user
        """

        data = {k:v for k, v in validated_data.items() if k != "password"}
        user = models.User.objects.create(**data)
        if "password" in validated_data:
            user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        """Update un user
        """
        
        instance.id = validated_data.get('id', instance.id)
        instance.email = validated_data.get('email', instance.email)
        instance.user_type = validated_data.get('user_type', instance.user_type)
        instance.contrat = validated_data.get('contrat', instance.contrat)
        instance.id_dealer = validated_data.get('id_dealer', instance.id_dealer)
        instance.default_alert_type = validated_data.get('default_alert_type', instance.default_alert_type)
        instance.set_password(validated_data['password'])
        instance.save()
        return instance

class UserProgramsSerializer(serializers.ModelSerializer):
    """Serialisation of user program
    """
    
    class Meta:
        model = models.UserPrograms
        fields = ('id', 'program_name', 'program_version', 'minimum_score', 'user_id', 'poste', 'cpe', 'sms_score', 'email_score', 'web_score', 'alert_type_default', 'is_vulnerable')

    def create(self, validated_data):
        """Create an user program
        """
        return models.UserPrograms.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Update an user program
        """
        instance.id = validated_data.get('id', instance.id)
        instance.program_name = validated_data.get('program_name', instance.program_name)
        instance.program_version = validated_data.get('program_version', instance.program_version)
        instance.minimum_score = validated_data.get('minimum_score', instance.minimum_score)
        instance.user_id = validated_data.get('user_id', instance.user_id)
        instance.poste = validated_data.get('poste', instance.poste)
        instance.sms_score = validated_data.get('sms_score', instance.sms_score)
        instance.email_score = validated_data.get('email_score', instance.email_score)
        instance.web_score = validated_data.get('web_score', instance.web_score)
        instance.alert_type_default = validated_data.get('alert_type_default', instance.alert_type_default)
        instance.save()
        return instance

class AlertSerializer(serializers.ModelSerializer):
    """Serialisation of user alerts
    """
    
    # program = UserProgramsSerializer()

    class Meta:
        model = models.Alert
        fields = ('id', 'user', 'program', 'number_cve', 'max_cvss', 'program_info')

    def create(self, validated_data):
        """Create an alert
        """
        return models.Alert.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Update an alert
        """
        instance.id = validated_data.get('id', instance.id)
        instance.user = validated_data.get('user', instance.user)
        instance.program = validated_data.get('program', instance.program)
        instance.cve = validated_data.get('cve', instance.cve)
        instance.save()
        return instance



class AlertSerializerDetail(serializers.ModelSerializer):
    """Serialisation of user alerts
    """

    program = UserProgramsSerializer()
    cve = CveSerializer(read_only=True, many=True)

    class Meta:
        model = models.Alert
        fields = ('id', 'user', 'program', 'cve')
