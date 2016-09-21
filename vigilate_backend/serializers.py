from rest_framework import serializers
from vigilate_backend import models
from rest_framework import status
from rest_framework.response import Response
from vulnerability_manager.serializers import CveSerializer
from vigilate_backend.utils import can_add_station

class UserSerializer(serializers.ModelSerializer):
    """Serialisation of User
    """

    class Meta:
        model = models.User
        fields = ('id', 'email', 'password', 'user_type', 'id_dealer', 'default_alert_type', 'phone', 'plan', 'plan_purchase_date')
        

    def create(self, validated_data):
        """Create an user
        """

        data = {k:v for k, v in validated_data.items() if not k in ['password', 'user_type', 'id_dealer', 'default_alert_type', 'plan', 'plan_purchase_date']}
        user = models.User.objects.create(**data)
        if "password" in validated_data:
            user.set_password(validated_data['password'])
        user.save()
        return user

    def validate(self, data):
        if not hasattr(self.instance, "id"):
            return data

        prev_state = models.User.objects.get(id=self.instance.id)
        if 'default_alert_type' in data and data['default_alert_type'] == models.User.SMS and\
           (('phone' in data and not data['phone']) or (not 'phone' in data and not prev_state.phone)):
            raise serializers.ValidationError({'phone': ['Cannot enable sms alert for an user without a phone number registered']})
        return data

    def update(self, instance, validated_data):
        """Update un user
        """
        
        instance.id = validated_data.get('id', instance.id)
        instance.email = validated_data.get('email', instance.email)
        instance.default_alert_type = validated_data.get('default_alert_type', instance.default_alert_type)
        instance.phone = validated_data.get('phone', instance.phone)
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance

class UserProgramsSerializer(serializers.ModelSerializer):
    """Serialisation of user program
    """
    
    class Meta:
        model = models.UserPrograms
        fields = ('id', 'program_name', 'program_version', 'minimum_score', 'user', 'poste', 'cpe', 'sms_score', 'email_score', 'web_score', 'sms_enabled', 'email_enabled', 'web_enabled', 'alert_type_default', 'alert_id')

    def create(self, validated_data):
        """Create an user program
        """
        validated_data['program_version'] = validated_data['program_version'][0]
        return models.UserPrograms.objects.create(**validated_data)

    def validate(self, data):
        if (not 'alert_type_default' in data or not data['alert_type_default']) and\
           ('sms_enabled' in data and data['sms_enabled']) and not data['user'].phone:
            raise serializers.ValidationError({'sms_enabled': ['Cannot enable sms alert for an user without a phone number registered']})
        return data

class AlertSerializer(serializers.ModelSerializer):
    """Serialisation of user alerts
    """


    class Meta:
        model = models.Alert
        fields = ('id', 'user', 'program', 'number_cve', 'max_cvss', 'program_info', 'view', 'state')

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
        instance.view = validated_data.get('view', instance.view)
        instance.save()
        return instance



class AlertSerializerDetail(serializers.ModelSerializer):
    """Serialisation of user alerts
    """

    program = UserProgramsSerializer()
    cve = CveSerializer(read_only=True, many=True)

    class Meta:
        model = models.Alert
        fields = ('id', 'user', 'program', 'cve', 'view')


class StationSerializer(serializers.ModelSerializer):
    """Serialisation of station
    """

    class Meta:
        model = models.Station
        fields = ('id', 'user', 'name', 'disabled')

    def validate(self, data):

        if not can_add_station(models.Station.objects.filter(user=data["user"].id).count(), data["user"]):
            raise serializers.ValidationError({'name': "You can't add more station with your current plan"})
        return data

        
class SessionSerializer(serializers.ModelSerializer):
    """Serialisation of session
    """

    class Meta:
        model = models.Session
        fields = ()

class PlansSerializer(serializers.ModelSerializer):
    """Serialisation of plans
    """

    class Meta:
        model = models.Plans
        fields = ('id', 'name', 'max_stations', 'price', 'validity_time')
