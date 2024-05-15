from Crypto.Util import number
import random

from src.cryptography.pedersen import Pedersen

class PedersenBVM:
    UNUSED = False
    USED = True
    CANDIDATE_NOT_FOUND = lambda self, x: 'Candidate with label {} does not exists'.format(x)
    VOTE_IS_FULL = 'Vote is already full'
    VOTE_SUCCESS = 'Vote recorded successfully'
    INVALID_DUMMY_TYPE = lambda self, x: 'Valid type is "used" or "unused"; received: ' + str(x)

    def __init__(self, config):
        self.security_level = config['security']            # 80
        self.num_of_voters = config['num_of_voters']
        self.num_of_candidates = len(config['candidate_labels'])
        self.num_of_dummy_votes = self.num_of_voters * self.num_of_candidates
        self.param = Pedersen.generate_param(self.security_level)
        self._generate_dummy_votes()
        self.candidate_data = self._setup_candidates(config['candidate_labels'])
        self.ballots = []
        self.num_of_received_votes = 0

    def vote(self, picked_candidate):
        vote_response = {}
        if self.vote_is_full():
            vote_response['ballot'] = {}
            vote_response['description'] = 'Vote is full'
            vote_response['accepted'] = False
            vote_response['id'] = -1
            return vote_response
        picked_candidate = picked_candidate.upper()
        if not self.label_exists(picked_candidate):
            raise ValueError(self.CANDIDATE_NOT_FOUND(picked_candidate))

        new_number = self._generate_fresh_random_number()
        fresh_vote = self._commit_vote(new_number)
        self.candidate_data[picked_candidate]['fresh'].append(fresh_vote)
        new_ballot = {}
        new_ballot['content'] = {}
        for label in self.candidate_data:
            if label == picked_candidate:
                new_ballot['content'][label] = fresh_vote[0]
                continue
            new_ballot['content'][label] = self._pick_random_dummy_vote(label)

        self.num_of_received_votes += 1
        new_ballot['id'] = self.num_of_received_votes
        self.ballots.append(new_ballot)
        self._sort_ballot_by_id()
        
        vote_response = {}
        vote_response['ballot'] = new_ballot['content']
        vote_response['description'] = self.VOTE_SUCCESS
        vote_response['accepted'] = True
        vote_response['id'] = self.num_of_received_votes
        return vote_response

    def verify_vote(self, commitment, vote, r_values):
        if not (isinstance(commitment, (int)) and isinstance(vote, (int)) \
            and isinstance(r_values, (int, list))):
            raise TypeError('Invalid commitment, vote, or r type!')
        return Pedersen.open(commitment, vote, r_values, self.param)

    def publish_unused_dummy(self):
        data = {}
        for label in self.candidate_data:
            data[label] = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.UNUSED:
                    data[label].append((dv[0], dv[1], dv[2]))
        return data

    def get_poll_result(self):
        poll_result = {}
        non_voters = (self.num_of_voters - self.num_of_received_votes)
        for label in self.candidate_data:
            label = label.upper()
            unused_dv = 0
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] is self.UNUSED:
                    unused_dv += 1
            tally = unused_dv - non_voters
            poll_result[label] = tally
        return poll_result

    def get_candidate_labels(self):
        candidate_labels = []
        for label in self.candidate_data:
            candidate_labels.append(label)
        return candidate_labels

    def get_candidate_dummies(self, label, status='unused'):
        label = label.upper()
        if not self.label_exists(label):
            raise ValueError(self.CANDIDATE_NOT_FOUND(label))
        if status == 'all':
            return [(dv[0], dv[1]) for dv in self.candidate_data[label]['dummy']]
        elif status == 'used':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.USED:
                    response.append((dv[0], dv[1]))
            return response
        elif status == 'unused':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.UNUSED:
                    response.append((dv[0], dv[1]))
            return response
        else:
            raise ValueError(self.INVALID_DUMMY_TYPE(status))

    def get_all_dummy_votes(self, status='unused'):
        response = {}
        for c in self.candidate_data:
            response[c] = self.get_candidate_dummy_votes(c, status=status)
        return response

    def get_candidate_dummy_votes(self, label, status='unused'):
        label = label.upper()
        if not self.label_exists(label):
            raise ValueError(self.CANDIDATE_NOT_FOUND(label))
        if status == 'all':
            return [dv[0] for dv in self.candidate_data[label]['dummy']]
        elif status == 'used':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.USED:
                    response.append(dv[0])
            return response
        elif status == 'unused':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.UNUSED:
                    response.append(dv[0])
            return response
        else:
            raise ValueError(self.INVALID_DUMMY_TYPE(status))

    def get_all_dummy_commitments(self, status='unused'):
        response = {}
        for c in self.candidate_data:
            response[c] = self.get_dummy_commitments(c, status=status)
        return response

    def get_dummy_commitments(self, label, status='unused'):
        label = label.upper()
        if not self.label_exists(label):
            raise ValueError(self.CANDIDATE_NOT_FOUND(label))
        if status == 'all':
            return [dv[1] for dv in self.candidate_data[label]['dummy']]
        elif status == 'used':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.USED:
                    response.append(dv[1])
            return response
        elif status == 'unused':
            response = []
            for dv in self.candidate_data[label]['dummy']:
                if dv[3] == self.UNUSED:
                    response.append(dv[1])
            return response
        else:
            raise ValueError(self.INVALID_DUMMY_TYPE(status))

    def get_all_fresh(self):
        response = {}
        for c in self.candidate_data:
            response[c] = self.get_fresh_votes(c)
        return response

    def get_fresh_votes(self, label):
        return [dv[0] for dv in self.candidate_data[label]['fresh']]

    def get_all_fresh_commitments(self):
        response = {}
        for c in self.candidate_data:
            response[c] = self.get_fresh_commitments(c)
        return response

    def get_fresh_commitments(self, label):
        return [dv[1] for dv in self.candidate_data[label]['fresh']]

    def get_ballots(self):
        return self.ballots
    
    def get_ballot_by_id(self, id):
        if id < 1 or id > len(self.ballots):
            raise ValueError('ID value out of range (received {})'.format(id))
        for bl in self.ballots:
            if bl['id'] == id:
                return bl
        else:
            return None

    def get_vote_count(self):
        return (self.num_of_received_votes, self.num_of_voters)
        
    def label_exists(self, label):
        return label.upper() in self.candidate_data

    def vote_is_full(self):
        return self.num_of_voters == self.num_of_received_votes

    def _generate_fresh_random_number(self):
        new_number = number.getRandomRange(1, self.security_level*self.num_of_dummy_votes)
        while (self._number_is_already_used(new_number)):
            new_number = number.getRandomRange(1, self.security_level*self.num_of_dummy_votes)
        return new_number

    def _number_is_already_used(self, new_number):
        for cnd in self.candidate_data:
            cnd_dv = [dv[0] for dv in self.candidate_data[cnd]['dummy']]
            if new_number in cnd_dv:
                return True
        return False

    def _commit_vote(self, vote):
        c, r = Pedersen.commit(vote, self.param)
        return (vote, c, r)

    def _pick_random_dummy_vote(self, label):
        idx = [i for i in range(len(self.candidate_data[label]['dummy']))]
        r = random.SystemRandom()
        r.shuffle(idx)
        for i in idx:
            dv = self.candidate_data[label]['dummy'][i]
            if dv[3] is self.UNUSED:
                self.candidate_data[label]['dummy'][i] = (*dv[:-1], self.USED)
                return dv[0]
        raise IndexError('All dummy votes taken')

    def _generate_dummy_votes(self):
        dummy_votes = []
        for _ in range(self.num_of_dummy_votes):
            new_dummy = number.getRandomRange(1, self.security_level*self.num_of_dummy_votes)
            while new_dummy in dummy_votes:
                new_dummy = number.getRandomRange(1, self.security_level*self.num_of_dummy_votes)
            dummy_votes.append(new_dummy)
        return dummy_votes

    def _setup_candidates(self, cadidate_labels):
        unused_dummy_votes = self._generate_dummy_votes()
        candidate_data = {}
        for label in cadidate_labels:
            label = label.upper()
            label = label.replace(' ', '-')
            candidate_data[label] = {}
            candidate_data[label]['dummy'] = []
            candidate_data[label]['fresh'] = []
            for _ in range(self.num_of_voters):
                random.shuffle(unused_dummy_votes)
                dv = unused_dummy_votes.pop()
                candidate_data[label]['dummy'].append((*self._commit_vote(dv), self.UNUSED))
        return candidate_data

    def _sort_ballot_by_id(self):
        temp_list = sorted(self.ballots, key = lambda k:k['id'])
        self.ballots = temp_list